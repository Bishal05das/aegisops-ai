package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/ports"
)

// SessionRepo persists refresh tokens.
type SessionRepo struct {
	base
}

// NewSessionRepo builds the adapter.
func NewSessionRepo(db *sql.DB) *SessionRepo { return &SessionRepo{base{db: db}} }

var _ ports.SessionRepository = (*SessionRepo)(nil)

const sessionColumns = `
	id, user_id, token_hash, family_id, rotated_to, rotated_at,
	revoked_at, revoked_reason, issued_ip, user_agent, expires_at, created_at`

// Create stores a newly minted refresh token.
func (r *SessionRepo) Create(ctx context.Context, t *user.RefreshToken) error {
	const op = "postgres.SessionRepo.Create"

	if err := t.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err := r.exec(ctx).ExecContext(ctx, `
		INSERT INTO refresh_tokens (
			id, user_id, token_hash, family_id, issued_ip, user_agent, expires_at, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		t.ID, t.UserID, t.TokenHash, t.FamilyID, t.IssuedIP, t.UserAgent, t.ExpiresAt, t.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%s: %w: token hash collision", op, shared.ErrAlreadyExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// GetByPlaintext looks a token up by hashing the presented value.
//
// The lookup is by digest, so the plaintext never reaches the database and a
// query log cannot leak it.
func (r *SessionRepo) GetByPlaintext(ctx context.Context, plaintext string) (*user.RefreshToken, error) {
	const op = "postgres.SessionRepo.GetByPlaintext"

	hash := user.HashRefreshToken(plaintext)
	t, err := scanSession(r.exec(ctx).QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM refresh_tokens WHERE token_hash = $1`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		// Deliberately says nothing about the token: an unrecognised value and
		// a revoked one must be indistinguishable to the caller.
		return nil, fmt.Errorf("%s: %w: refresh token is not recognised", op, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return t, nil
}

// Rotate atomically marks a token used and stores its replacement.
//
// Both writes must land together. If the old token were marked rotated but the
// new one failed to insert, the user would hold a credential the server has no
// record of and be logged out; if the new token were stored but the old not
// marked, the old would stay valid forever and rotation would be decorative.
//
// The UPDATE carries `AND rotated_at IS NULL`, so two concurrent refreshes with
// the same token cannot both succeed: the second matches zero rows and is
// reported as a replay. That is the race a naive read-then-write would lose.
func (r *SessionRepo) Rotate(ctx context.Context, oldID shared.ID, next *user.RefreshToken) error {
	const op = "postgres.SessionRepo.Rotate"

	if err := next.Validate(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return NewTxManager(r.db).WithinTx(ctx, func(ctx context.Context) error {
		ex := r.exec(ctx)

		if _, err := ex.ExecContext(ctx, `
			INSERT INTO refresh_tokens (
				id, user_id, token_hash, family_id, issued_ip, user_agent, expires_at, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			next.ID, next.UserID, next.TokenHash, next.FamilyID,
			next.IssuedIP, next.UserAgent, next.ExpiresAt, next.CreatedAt,
		); err != nil {
			return fmt.Errorf("%s: insert replacement: %w", op, err)
		}

		res, err := ex.ExecContext(ctx, `
			UPDATE refresh_tokens
			SET rotated_to = $1, rotated_at = $2
			WHERE id = $3 AND rotated_at IS NULL`,
			next.ID, next.CreatedAt, oldID)
		if err != nil {
			return fmt.Errorf("%s: mark rotated: %w", op, err)
		}

		affected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("%s: rows affected: %w", op, err)
		}
		if affected == 0 {
			// Someone rotated it between our read and this write. Rolling back
			// discards the replacement we just inserted, which is correct: the
			// caller must treat this as a replay.
			return fmt.Errorf("%s: %w: token was rotated concurrently", op, shared.ErrConflict)
		}
		return nil
	})
}

// RevokeFamily revokes every unrevoked token descended from one login.
//
// Called when a rotated token is replayed. The replay means either the token was
// stolen after the legitimate client rotated it, or the client is racing itself.
// Only one of those is benign, and the two are indistinguishable from here — so
// the whole lineage is invalidated and the user re-authenticates. Choosing the
// benign interpretation would leave a thief holding a valid session.
func (r *SessionRepo) RevokeFamily(ctx context.Context, familyID shared.ID, reason string, at time.Time) (int64, error) {
	const op = "postgres.SessionRepo.RevokeFamily"

	res, err := r.exec(ctx).ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = $1, revoked_reason = $2
		WHERE family_id = $3 AND revoked_at IS NULL`,
		at, reason, familyID)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%s: rows affected: %w", op, err)
	}
	return n, nil
}

// RevokeAllForUser revokes every live token a user holds — logout everywhere,
// and the correct response to a password change or a role downgrade.
func (r *SessionRepo) RevokeAllForUser(ctx context.Context, userID user.ID, reason string, at time.Time) (int64, error) {
	const op = "postgres.SessionRepo.RevokeAllForUser"

	res, err := r.exec(ctx).ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = $1, revoked_reason = $2
		WHERE user_id = $3 AND revoked_at IS NULL`,
		at, reason, userID)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%s: rows affected: %w", op, err)
	}
	return n, nil
}

// Revoke invalidates one token, which is what logout does.
func (r *SessionRepo) Revoke(ctx context.Context, id shared.ID, reason string, at time.Time) error {
	const op = "postgres.SessionRepo.Revoke"

	res, err := r.exec(ctx).ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = $1, revoked_reason = $2
		WHERE id = $3 AND revoked_at IS NULL`,
		at, reason, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	// A no-op when already revoked: logging out twice is not an error.
	if _, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("%s: rows affected: %w", op, err)
	}
	return nil
}

// DeleteExpired removes tokens that expired before the cutoff.
//
// Housekeeping, not security: an expired token is already unusable. This keeps
// the table from growing without bound, since every login adds a row and every
// refresh adds another.
func (r *SessionRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	const op = "postgres.SessionRepo.DeleteExpired"

	res, err := r.exec(ctx).ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%s: rows affected: %w", op, err)
	}
	return n, nil
}

// ListForUser returns a user's live sessions, newest first, so the /me endpoint
// can show where they are logged in.
func (r *SessionRepo) ListForUser(ctx context.Context, userID user.ID) ([]*user.RefreshToken, error) {
	const op = "postgres.SessionRepo.ListForUser"

	rows, err := r.exec(ctx).QueryContext(ctx,
		`SELECT `+sessionColumns+` FROM refresh_tokens
		 WHERE user_id = $1 AND revoked_at IS NULL AND rotated_at IS NULL AND expires_at > now()
		 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	var out []*user.RefreshToken
	for rows.Next() {
		t, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: iterate: %w", op, err)
	}
	return out, nil
}

func scanSession(s rowScanner) (*user.RefreshToken, error) {
	var (
		t         user.RefreshToken
		rotatedTo sql.Null[shared.ID]
	)
	err := s.Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.FamilyID, &rotatedTo, &t.RotatedAt,
		&t.RevokedAt, &t.RevokedReason, &t.IssuedIP, &t.UserAgent,
		&t.ExpiresAt, &t.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if rotatedTo.Valid {
		id := rotatedTo.V
		t.RotatedTo = &id
	}
	return &t, nil
}
