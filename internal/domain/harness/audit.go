package harness

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
)

// Outcome is what actually happened to a request.
type Outcome string

// Audit outcomes.
const (
	OutcomeAllowed  Outcome = "allowed"  // passed the gates, not yet run
	OutcomeDenied   Outcome = "denied"   // a gate rejected it
	OutcomeExecuted Outcome = "executed" // ran successfully
	OutcomeFailed   Outcome = "failed"   // ran and failed
	OutcomeDryRun   Outcome = "dry_run"  // intent logged, infrastructure untouched
)

// Valid reports whether the outcome is defined.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeAllowed, OutcomeDenied, OutcomeExecuted, OutcomeFailed, OutcomeDryRun:
		return true
	default:
		return false
	}
}

// AuditEntry is one immutable row of the ledger.
//
// The property that matters most: **rejections are recorded as fully as
// executions.** A harness that only logs what it executed throws away its single
// most valuable signal. "The Action Agent requested delete_database at 03:14,
// reasoning X, and was blocked by policy" is the line that tells you the model
// has drifted — and you only get it if the audit write is unconditional.
//
// Entries are hash-chained. Each row commits to its predecessor, so removing or
// editing a row breaks every hash after it. This does not stop an attacker with
// database write access from rewriting the whole chain, and does not pretend to;
// it makes *selective* tampering — quietly deleting the one row showing what an
// agent tried to do — detectable by verification.
type AuditEntry struct {
	ID         shared.ID
	Seq        int64
	OccurredAt time.Time

	ActorType string // agent | user | system
	ActorID   shared.ID
	ActorName string

	Action       string
	ResourceType string
	ResourceID   string

	// IncidentID is intentionally NOT a foreign key in the schema. The ledger
	// outlives everything it references: deleting an incident must never erase
	// the record that an agent tried to drop a table.
	IncidentID *shared.ID
	ToolCallID *shared.ID

	Outcome Outcome
	Reason  string

	// Params is redacted before it reaches here. Tool arguments are arbitrary
	// maps assembled by an LLM and may contain anything the model read from the
	// environment, so logger.RedactMap runs over them first.
	Params map[string]any
	Result map[string]any
	Error  string

	// RequestID correlates the entry with the HTTP request and log lines that
	// produced it; BuildVersion records which binary made the decision.
	RequestID    string
	BuildVersion string

	PrevHash []byte
	Hash     []byte
}

// MaxAuditReasonLen bounds the recorded justification.
const MaxAuditReasonLen = 10000

// NewAuditEntry builds an unhashed entry. The repository assigns Seq, PrevHash
// and Hash inside the insert transaction, because the chain must be computed
// against the row that is actually the predecessor — which is only knowable
// under the lock the insert holds.
func NewAuditEntry(clock shared.Clock, actorType, actorName, action string, outcome Outcome) *AuditEntry {
	return &AuditEntry{
		ID:         shared.NewID(),
		OccurredAt: clock.Now(),
		ActorType:  actorType,
		ActorName:  actorName,
		Action:     action,
		Outcome:    outcome,
		Params:     map[string]any{},
		Result:     map[string]any{},
	}
}

// Validate checks the entry's invariants.
func (a *AuditEntry) Validate() error {
	v := shared.NewValidator("audit_log")
	v.NotZeroID(a.ID, "id")
	v.Required(a.ActorType, "actor_type")
	v.Required(a.Action, "action")
	v.Check(a.Outcome.Valid(), "outcome",
		"must be one of: allowed, denied, executed, failed, dry_run")
	v.MaxLen(a.Reason, "reason", MaxAuditReasonLen)
	v.Check(!a.OccurredAt.IsZero(), "occurred_at", "is required")
	return v.Err()
}

// ComputeHash derives this entry's chain hash from its predecessor and its own
// identifying fields.
//
// Only fields that must not change are committed to. Deliberately excluded are
// Params and Result: they are JSON maps whose serialisation order is not stable
// across Go versions or driver round-trips, so including them would produce
// spurious verification failures. The fields that carry the meaning — who,
// what, when, and the verdict — are all covered.
//
// Length-prefixing every field prevents a concatenation ambiguity: without it,
// ("ab","c") and ("a","bc") would hash identically, letting a forged entry
// collide with a real one.
//
// The timestamp is canonicalised to microseconds. This is not cosmetic: a hash
// is only useful if it can be recomputed from stored data, and PostgreSQL's
// TIMESTAMPTZ holds microseconds while Go's time.Time holds nanoseconds. Hashing
// the nanosecond form would make every entry fail verification the moment it was
// read back — the chain would report tampering on a database nobody had touched,
// which is worse than having no chain at all.
//
// Any storage backend used in future must preserve at least microsecond
// precision, or this canonicalisation has to move down to match it.
func (a *AuditEntry) ComputeHash(prev []byte) []byte {
	h := sha256.New()
	h.Write(prev)

	writeField := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}

	// Two's-complement reinterpretation, not a range conversion: Seq is always
	// positive in practice, and the hash only needs the bit pattern to be a
	// deterministic function of the value.
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], uint64(a.Seq)) //nolint:gosec // bit pattern, not a numeric range conversion
	h.Write(seq[:])

	writeField(a.ID.String())
	writeField(a.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano))
	writeField(a.ActorType)
	writeField(a.ActorID.String())
	writeField(a.ActorName)
	writeField(a.Action)
	writeField(a.ResourceType)
	writeField(a.ResourceID)
	writeField(string(a.Outcome))
	writeField(a.Reason)
	writeField(a.Error)
	writeField(a.RequestID)
	writeField(a.BuildVersion)

	if a.IncidentID != nil {
		writeField(a.IncidentID.String())
	} else {
		writeField("")
	}
	if a.ToolCallID != nil {
		writeField(a.ToolCallID.String())
	} else {
		writeField("")
	}

	return h.Sum(nil)
}

// HashHex renders the chain hash for display.
func (a *AuditEntry) HashHex() string { return hex.EncodeToString(a.Hash) }

// ChainVerification reports the result of verifying a run of ledger entries.
type ChainVerification struct {
	Checked int
	Valid   bool
	// BrokenAtSeq is the first entry whose recorded hash does not match a
	// recomputation, or 0 when the chain is intact.
	BrokenAtSeq int64
	Reason      string
}

// VerifyChain recomputes the hash chain over entries, which must be ordered by
// ascending Seq and start either at the genesis entry or at a known-good hash.
func VerifyChain(entries []*AuditEntry, startHash []byte) ChainVerification {
	prev := startHash
	for _, e := range entries {
		want := e.ComputeHash(prev)
		if !equalBytes(want, e.Hash) {
			return ChainVerification{
				Checked:     len(entries),
				Valid:       false,
				BrokenAtSeq: e.Seq,
				Reason: "entry hash does not match a recomputation; the row was " +
					"altered, or a preceding row was removed",
			}
		}
		if !equalBytes(prev, e.PrevHash) {
			return ChainVerification{
				Checked:     len(entries),
				Valid:       false,
				BrokenAtSeq: e.Seq,
				Reason:      "prev_hash does not match the preceding entry; a row is missing",
			}
		}
		prev = e.Hash
	}
	return ChainVerification{Checked: len(entries), Valid: true}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
