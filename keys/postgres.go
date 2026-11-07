package keys

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/vennet-developers/cauthy-sdk-go/internal/cfgerr"
)

// DefaultTable is the table Postgres keeps the keys in: the one `cauthy init`
// creates and @cauthyhq/node's postgresKeyStore reads.
const DefaultTable = "cauthy_pact_keys"

var tableRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// TableSQL is the table a Postgres store keeps the keys in, for the
// application's own migrations. The store never creates it.
func TableSQL(table string) (string, error) {
	if !tableRE.MatchString(table) {
		return "", cfgerr.New("the key table's name must be a plain SQL identifier: %s", table)
	}
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  kid        TEXT        PRIMARY KEY,
  public_jwk JSONB       NOT NULL,
  sealed     TEXT        NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);`, table), nil
}

// Postgres is a Store in the table cauthy_pact_keys of the application's
// Postgres database, through any database/sql driver (pgx's stdlib, lib/pq).
func Postgres(db *sql.DB) Store {
	s, _ := PostgresTable(db, DefaultTable)
	return s
}

// PostgresTable is Postgres with another table name.
func PostgresTable(db *sql.DB, table string) (Store, error) {
	if _, err := TableSQL(table); err != nil {
		return nil, err
	}
	return &postgres{db: db, table: table}, nil
}

type postgres struct {
	db    *sql.DB
	table string
}

const stamp = "2006-01-02T15:04:05.000Z07:00"

// Timestamp is t as a StoredKey's CreatedAt: UTC, milliseconds, "Z".
func Timestamp(t time.Time) string { return t.UTC().Format(stamp) }

func (p *postgres) List(ctx context.Context) ([]StoredKey, error) {
	rows, err := p.db.QueryContext(ctx, fmt.Sprintf(`SELECT kid, public_jwk, sealed, created_at FROM %s`, p.table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredKey{}
	for rows.Next() {
		var (
			k       StoredKey
			jwk, at any
		)
		if err := rows.Scan(&k.Kid, &jwk, &k.Sealed, &at); err != nil {
			return nil, err
		}
		switch v := jwk.(type) {
		case []byte:
			err = json.Unmarshal(v, &k.PublicJWK)
		case string:
			err = json.Unmarshal([]byte(v), &k.PublicJWK)
		case map[string]any:
			k.PublicJWK = v
		default:
			err = fmt.Errorf("cauthy: public_jwk of %s is a %T", k.Kid, jwk)
		}
		if err != nil {
			return nil, err
		}
		switch v := at.(type) {
		case time.Time:
			k.CreatedAt = Timestamp(v)
		case string:
			if k.CreatedAt, err = parseStamp(v); err != nil {
				return nil, fmt.Errorf("cauthy: created_at of %s: %w", k.Kid, err)
			}
		case []byte:
			if k.CreatedAt, err = parseStamp(string(v)); err != nil {
				return nil, fmt.Errorf("cauthy: created_at of %s: %w", k.Kid, err)
			}
		default:
			return nil, fmt.Errorf("cauthy: created_at of %s is a %T", k.Kid, at)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// exec runs query with every {table} replaced by the store's table.
func (p *postgres) exec(ctx context.Context, query string, args ...any) error {
	_, err := p.db.ExecContext(ctx, strings.ReplaceAll(query, "{table}", p.table), args...)
	return err
}

// parseStamp reads a timestamptz a driver gave as text: RFC 3339, or
// Postgres's own "2006-01-02 15:04:05.999999-07".
func parseStamp(s string) (string, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		if t, err = time.Parse("2006-01-02 15:04:05.999999-07", s); err != nil {
			return "", err
		}
	}
	return Timestamp(t), nil
}

func jsonOf(m map[string]any) string {
	raw, _ := json.Marshal(m)
	return string(raw)
}

func (p *postgres) Add(ctx context.Context, k StoredKey) error {
	return p.exec(ctx, `INSERT INTO {table} (kid, public_jwk, sealed, created_at) VALUES ($1, $2::jsonb, $3, $4::timestamptz) ON CONFLICT (kid) DO NOTHING`,
		k.Kid, jsonOf(k.PublicJWK), k.Sealed, k.CreatedAt)
}

// AddFirst inserts inside a transaction that first takes the table's
// transaction-scoped advisory lock: instances starting together queue on it,
// so the second sees the first's key and keeps none of its own. Without the
// lock, two NOT EXISTS checks under READ COMMITTED can both pass.
func (p *postgres) AddFirst(ctx context.Context, k StoredKey) (err error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	// The table name is a checked plain identifier (tableRE).
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`SELECT pg_advisory_xact_lock(hashtext('%s'))`, p.table)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, strings.ReplaceAll(`INSERT INTO {table} (kid, public_jwk, sealed, created_at) SELECT $1, $2::jsonb, $3, $4::timestamptz WHERE NOT EXISTS (SELECT 1 FROM {table}) ON CONFLICT (kid) DO NOTHING`, "{table}", p.table),
		k.Kid, jsonOf(k.PublicJWK), k.Sealed, k.CreatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *postgres) Update(ctx context.Context, k StoredKey) error {
	return p.exec(ctx, `UPDATE {table} SET sealed = $2 WHERE kid = $1`, k.Kid, k.Sealed)
}

func (p *postgres) Remove(ctx context.Context, kid string) error {
	return p.exec(ctx, `DELETE FROM {table} WHERE kid = $1`, kid)
}
