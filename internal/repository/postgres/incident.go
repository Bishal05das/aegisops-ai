package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/incident"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// IncidentRepo persists incidents and their timelines.
type IncidentRepo struct {
	base
}

// NewIncidentRepo builds the adapter.
func NewIncidentRepo(db *sql.DB) *IncidentRepo { return &IncidentRepo{base{db: db}} }

var _ ports.IncidentRepository = (*IncidentRepo)(nil)

// incidentColumns is the canonical select list. Named explicitly rather than
// SELECT *, so adding a column cannot silently break Scan's positional order.
const incidentColumns = `
	id, title, description, severity, status, source,
	service, environment, labels,
	root_cause, confidence,
	detected_at, acknowledged_at, resolved_at, closed_at,
	created_by, created_at, updated_at, version`

// Create inserts a new incident.
func (r *IncidentRepo) Create(ctx context.Context, inc *incident.Incident) error {
	const op = "postgres.IncidentRepo.Create"

	if err := inc.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	labels, err := marshalJSON(inc.Labels)
	if err != nil {
		return fmt.Errorf("%s: encode labels: %w", op, err)
	}

	_, err = r.exec(ctx).ExecContext(ctx, `
		INSERT INTO incidents (
			id, title, description, severity, status, source,
			service, environment, labels, root_cause, confidence,
			detected_at, acknowledged_at, resolved_at, closed_at,
			created_by, created_at, updated_at, version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		inc.ID, inc.Title, inc.Description, string(inc.Severity), string(inc.Status), string(inc.Source),
		inc.Service, inc.Environment, labels, inc.RootCause, inc.Confidence,
		inc.DetectedAt, inc.AcknowledgedAt, inc.ResolvedAt, inc.ClosedAt,
		nullID(inc.CreatedBy), inc.CreatedAt, inc.UpdatedAt, inc.Version,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%s: %w: incident %s", op, shared.ErrAlreadyExists, inc.ID)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Get returns one incident, or shared.ErrNotFound.
func (r *IncidentRepo) Get(ctx context.Context, id incident.ID) (*incident.Incident, error) {
	const op = "postgres.IncidentRepo.Get"

	row := r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+incidentColumns+` FROM incidents WHERE id = $1`, id)

	inc, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: %w: incident %s", op, shared.ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return inc, nil
}

// Update writes an incident using optimistic locking.
//
// The WHERE clause carries the version the caller read. If another writer got
// there first the row no longer matches, zero rows are affected, and this
// returns shared.ErrConflict rather than silently discarding the caller's work.
//
// Seven agents mutate one incident concurrently, so this is not a theoretical
// concern: without it, the Diagnosis Agent writing a root cause and the
// Monitoring Agent writing a status would routinely overwrite each other.
func (r *IncidentRepo) Update(ctx context.Context, inc *incident.Incident) error {
	const op = "postgres.IncidentRepo.Update"

	if err := inc.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	labels, err := marshalJSON(inc.Labels)
	if err != nil {
		return fmt.Errorf("%s: encode labels: %w", op, err)
	}

	res, err := r.exec(ctx).ExecContext(ctx, `
		UPDATE incidents SET
			title = $1, description = $2, severity = $3, status = $4, source = $5,
			service = $6, environment = $7, labels = $8,
			root_cause = $9, confidence = $10,
			detected_at = $11, acknowledged_at = $12, resolved_at = $13, closed_at = $14,
			updated_at = $15, version = version + 1
		WHERE id = $16 AND version = $17`,
		inc.Title, inc.Description, string(inc.Severity), string(inc.Status), string(inc.Source),
		inc.Service, inc.Environment, labels, inc.RootCause, inc.Confidence,
		inc.DetectedAt, inc.AcknowledgedAt, inc.ResolvedAt, inc.ClosedAt,
		inc.UpdatedAt, inc.ID, inc.Version,
	)
	if err != nil {
		if isCheckViolation(err) {
			return fmt.Errorf("%s: %w: the database rejected the row: %w", op, shared.ErrValidation, err)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: rows affected: %w", op, err)
	}
	if affected == 0 {
		// Distinguish "gone" from "changed underneath us": the caller retries a
		// conflict but must not retry a deletion.
		var exists bool
		if err := r.exec(ctx).QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM incidents WHERE id = $1)`, inc.ID).Scan(&exists); err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		if !exists {
			return fmt.Errorf("%s: %w: incident %s", op, shared.ErrNotFound, inc.ID)
		}
		return fmt.Errorf("%s: %w: incident %s was modified concurrently (expected version %d)",
			op, shared.ErrConflict, inc.ID, inc.Version)
	}

	// Advance in place so the caller can keep using the object for a further
	// update without re-reading.
	inc.Version++
	return nil
}

// List returns a filtered page of incidents, newest first.
func (r *IncidentRepo) List(ctx context.Context, f ports.IncidentFilter, p ports.Page) (ports.PageResult[*incident.Incident], error) {
	const op = "postgres.IncidentRepo.List"
	var zero ports.PageResult[*incident.Incident]

	p = p.Normalise()
	where, args := incidentWhere(f)

	// Keyset pagination on (detected_at, id). The id tiebreaks so that
	// incidents sharing a timestamp — common, since alerts arrive in bursts —
	// still have a total order and cannot be skipped or repeated across pages.
	if p.Cursor != "" {
		ts, id, err := decodeCursor(p.Cursor)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		args = append(args, ts, id)
		where = append(where, fmt.Sprintf("(detected_at, id) < ($%d, $%d)", len(args)-1, len(args)))
	}

	// Fetch one extra row to learn whether another page exists, without a
	// second COUNT query.
	args = append(args, p.Limit+1)
	query := `SELECT ` + incidentColumns + ` FROM incidents` +
		whereClause(where) +
		` ORDER BY detected_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.exec(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]*incident.Incident, 0, p.Limit)
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		items = append(items, inc)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("%s: iterate: %w", op, err)
	}

	result := ports.PageResult[*incident.Incident]{Items: items}
	if len(items) > p.Limit {
		result.Items = items[:p.Limit]
		result.HasMore = true
		last := result.Items[len(result.Items)-1]
		result.NextCursor = encodeCursor(last.DetectedAt, last.ID)
	}
	return result, nil
}

// Count returns how many incidents match a filter.
func (r *IncidentRepo) Count(ctx context.Context, f ports.IncidentFilter) (int64, error) {
	const op = "postgres.IncidentRepo.Count"

	where, args := incidentWhere(f)
	var n int64
	err := r.exec(ctx).QueryRowContext(ctx,
		`SELECT count(*) FROM incidents`+whereClause(where), args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return n, nil
}

// AppendEvent adds one timeline entry, assigning its sequence.
//
// The sequence is computed in the same statement as the insert. Reading the max
// and then inserting would race: two agents appending concurrently would both
// read the same maximum and one insert would fail on the unique index — or
// worse, succeed with a duplicate if the index were missing.
func (r *IncidentRepo) AppendEvent(ctx context.Context, ev *incident.Event) error {
	const op = "postgres.IncidentRepo.AppendEvent"

	if err := ev.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	payload, err := marshalJSON(ev.Payload)
	if err != nil {
		return fmt.Errorf("%s: encode payload: %w", op, err)
	}

	err = r.exec(ctx).QueryRowContext(ctx, `
		INSERT INTO incident_events (
			id, incident_id, seq, type, actor_type, actor_id, actor_name,
			message, payload, occurred_at
		)
		SELECT $1, $2,
		       COALESCE((SELECT max(seq) FROM incident_events WHERE incident_id = $2), 0) + 1,
		       $3, $4, $5, $6, $7, $8, $9
		RETURNING seq`,
		ev.ID, ev.IncidentID, string(ev.Type), string(ev.ActorType),
		nullID(ev.ActorID), ev.ActorName, ev.Message, payload, ev.OccurredAt,
	).Scan(&ev.Seq)

	if err != nil {
		if isUniqueViolation(err) {
			// Two appends raced past the subselect. The caller retries; the
			// second attempt reads the now-higher maximum.
			return fmt.Errorf("%s: %w: concurrent append to incident %s", op, shared.ErrConflict, ev.IncidentID)
		}
		if sqlState(err) == codeForeignKeyViolation {
			return fmt.Errorf("%s: %w: incident %s", op, shared.ErrNotFound, ev.IncidentID)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Events returns an incident's timeline in ascending sequence order.
func (r *IncidentRepo) Events(ctx context.Context, id incident.ID, p ports.Page) (ports.PageResult[*incident.Event], error) {
	const op = "postgres.IncidentRepo.Events"
	var zero ports.PageResult[*incident.Event]

	p = p.Normalise()
	args := []any{id}
	where := []string{"incident_id = $1"}

	// The timeline reads forward, so its cursor is the sequence number — an
	// integer, and already unique per incident.
	if p.Cursor != "" {
		after, err := strconv.ParseInt(p.Cursor, 10, 64)
		if err != nil {
			return zero, fmt.Errorf("%s: %w: cursor %q is not a sequence number",
				op, shared.ErrValidation, p.Cursor)
		}
		args = append(args, after)
		where = append(where, fmt.Sprintf("seq > $%d", len(args)))
	}

	args = append(args, p.Limit+1)
	query := `SELECT id, incident_id, seq, type, actor_type, actor_id, actor_name,
	                 message, payload, occurred_at
	          FROM incident_events` + whereClause(where) +
		` ORDER BY seq ASC LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.exec(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]*incident.Event, 0, p.Limit)
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return zero, fmt.Errorf("%s: %w", op, err)
		}
		items = append(items, ev)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("%s: iterate: %w", op, err)
	}

	result := ports.PageResult[*incident.Event]{Items: items}
	if len(items) > p.Limit {
		result.Items = items[:p.Limit]
		result.HasMore = true
		result.NextCursor = strconv.FormatInt(result.Items[len(result.Items)-1].Seq, 10)
	}
	return result, nil
}

// incidentWhere builds the predicate list and its arguments from a filter.
func incidentWhere(f ports.IncidentFilter) ([]string, []any) {
	var where []string
	var args []any

	add := func(clause string, values ...any) {
		args = append(args, values...)
		where = append(where, clause)
	}

	if len(f.Statuses) > 0 {
		args = append(args, stringsOf(f.Statuses))
		where = append(where, fmt.Sprintf("status = ANY($%d)", len(args)))
	}
	if len(f.Severities) > 0 {
		args = append(args, stringsOf(f.Severities))
		where = append(where, fmt.Sprintf("severity = ANY($%d)", len(args)))
	}
	if f.Service != "" {
		add(fmt.Sprintf("service = $%d", len(args)+1), f.Service)
	}
	if f.Environment != "" {
		add(fmt.Sprintf("environment = $%d", len(args)+1), f.Environment)
	}
	if f.Source != "" {
		add(fmt.Sprintf("source = $%d", len(args)+1), string(f.Source))
	}
	if f.ActiveOnly {
		// Matches the partial index incidents_active_idx exactly, so the planner
		// uses it rather than scanning.
		where = append(where, "status NOT IN ('resolved', 'closed', 'failed')")
	}
	if f.Since != nil {
		add(fmt.Sprintf("detected_at >= $%d", len(args)+1), *f.Since)
	}
	if f.Until != nil {
		add(fmt.Sprintf("detected_at <= $%d", len(args)+1), *f.Until)
	}
	if f.Search != "" {
		// ILIKE with leading wildcard, served by the trigram GIN index. A btree
		// index cannot help a leading %, which is why pg_trgm is installed.
		args = append(args, "%"+f.Search+"%")
		where = append(where, fmt.Sprintf("(title ILIKE $%d OR description ILIKE $%d)", len(args), len(args)))
	}
	return where, args
}

func whereClause(where []string) string {
	if len(where) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(where, " AND ")
}

// stringsOf converts a slice of string-kinded domain values into []string for
// use with `= ANY($n)`.
//
// One placeholder regardless of how many values there are. Building
// "IN ($1,$2,$3)" instead would produce a different query text for every
// distinct filter length, defeating the driver's statement cache and the
// database's plan cache.
//
// A []string is passed rather than a hand-built "{a,b}" array literal: pgx
// encodes the slice as a real text[], so a value containing a comma or brace
// cannot corrupt the literal. These are enum values today, but that will not
// remain true of every filter.
func stringsOf[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// rowScanner unifies *sql.Row and *sql.Rows so one scan helper serves both.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanIncident(s rowScanner) (*incident.Incident, error) {
	var (
		inc       incident.Incident
		severity  string
		status    string
		source    string
		labels    []byte
		createdBy sql.Null[shared.ID]
	)
	err := s.Scan(
		&inc.ID, &inc.Title, &inc.Description, &severity, &status, &source,
		&inc.Service, &inc.Environment, &labels,
		&inc.RootCause, &inc.Confidence,
		&inc.DetectedAt, &inc.AcknowledgedAt, &inc.ResolvedAt, &inc.ClosedAt,
		&createdBy, &inc.CreatedAt, &inc.UpdatedAt, &inc.Version,
	)
	if err != nil {
		return nil, err
	}

	inc.Severity = incident.Severity(severity)
	inc.Status = incident.Status(status)
	inc.Source = incident.Source(source)
	if createdBy.Valid {
		inc.CreatedBy = createdBy.V
	}
	if err := unmarshalJSON(labels, &inc.Labels); err != nil {
		return nil, fmt.Errorf("decode labels: %w", err)
	}
	if inc.Labels == nil {
		inc.Labels = map[string]string{}
	}
	return &inc, nil
}

func scanEvent(s rowScanner) (*incident.Event, error) {
	var (
		ev        incident.Event
		typ       string
		actorType string
		actorID   sql.Null[shared.ID]
		payload   []byte
	)
	err := s.Scan(
		&ev.ID, &ev.IncidentID, &ev.Seq, &typ, &actorType, &actorID, &ev.ActorName,
		&ev.Message, &payload, &ev.OccurredAt,
	)
	if err != nil {
		return nil, err
	}

	ev.Type = incident.EventType(typ)
	ev.ActorType = incident.ActorType(actorType)
	if actorID.Valid {
		ev.ActorID = actorID.V
	}
	if err := unmarshalJSON(payload, &ev.Payload); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	if ev.Payload == nil {
		ev.Payload = map[string]any{}
	}
	return &ev, nil
}

// --- shared helpers -------------------------------------------------------

// nullID converts a zero ID to SQL NULL, so an unset optional FK is stored as
// NULL rather than as an all-zeroes UUID that would violate the constraint.
func nullID(id shared.ID) any {
	if id.IsZero() {
		return nil
	}
	return id
}

func marshalJSON(v any) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(v)
}

func unmarshalJSON(data []byte, dst any) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, dst)
}

// encodeCursor packs a keyset position into an opaque token.
//
// Opaque on purpose: a client that parses a cursor starts depending on the sort
// key, which then cannot change without breaking them. Base64 signals "this is
// ours, do not read it" without pretending to be a security boundary.
func encodeCursor(ts time.Time, id shared.ID) string {
	raw := ts.UTC().Format(time.RFC3339Nano) + "|" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(cursor string) (time.Time, shared.ID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, shared.Nil, fmt.Errorf("%w: cursor is not valid base64", shared.ErrValidation)
	}
	tsPart, idPart, found := strings.Cut(string(raw), "|")
	if !found {
		return time.Time{}, shared.Nil, fmt.Errorf("%w: malformed cursor", shared.ErrValidation)
	}
	ts, err := time.Parse(time.RFC3339Nano, tsPart)
	if err != nil {
		return time.Time{}, shared.Nil, fmt.Errorf("%w: cursor timestamp is invalid", shared.ErrValidation)
	}
	id, err := shared.ParseID(idPart)
	if err != nil {
		return time.Time{}, shared.Nil, fmt.Errorf("%w: cursor id is invalid", shared.ErrValidation)
	}
	return ts, id, nil
}
