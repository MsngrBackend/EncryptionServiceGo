package encryption

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PublicKey struct {
	UserID    string    `json:"user_id"`
	PublicKey string    `json:"public_key"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) EnsureSchema(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS encryption_public_keys (
			user_id TEXT PRIMARY KEY,
			public_key TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func (r *Repository) UpsertPublicKey(ctx context.Context, userID, publicKey string) (*PublicKey, error) {
	key := &PublicKey{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO encryption_public_keys (user_id, public_key, algorithm)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		SET public_key = EXCLUDED.public_key,
		    algorithm = EXCLUDED.algorithm,
		    updated_at = NOW()
		RETURNING user_id, public_key, algorithm, created_at, updated_at
	`, userID, publicKey, Algorithm).Scan(
		&key.UserID,
		&key.PublicKey,
		&key.Algorithm,
		&key.CreatedAt,
		&key.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (r *Repository) GetPublicKey(ctx context.Context, userID string) (*PublicKey, error) {
	key := &PublicKey{}
	err := r.pool.QueryRow(ctx, `
		SELECT user_id, public_key, algorithm, created_at, updated_at
		FROM encryption_public_keys
		WHERE user_id = $1
	`, userID).Scan(
		&key.UserID,
		&key.PublicKey,
		&key.Algorithm,
		&key.CreatedAt,
		&key.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (r *Repository) LookupPublicKeys(ctx context.Context, userIDs []string) ([]*PublicKey, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT user_id, public_key, algorithm, created_at, updated_at
		FROM encryption_public_keys
		WHERE user_id = ANY($1)
		ORDER BY user_id
	`, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]*PublicKey, 0)
	for rows.Next() {
		key := &PublicKey{}
		if err := rows.Scan(
			&key.UserID,
			&key.PublicKey,
			&key.Algorithm,
			&key.CreatedAt,
			&key.UpdatedAt,
		); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
