package keys

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a database/sql driver that keeps a key table in memory and
// understands exactly the five statements the store sends, so the test sees
// the SQL itself. A real Postgres runs them in CI's postgres job.
type recorder struct {
	mu   sync.Mutex
	rows map[string][3]any // kid → public_jwk, sealed, created_at
	sent []string
}

func (r *recorder) Open(string) (driver.Conn, error) { return &conn{r}, nil }

type conn struct{ r *recorder }

func (c *conn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no prepare") }
func (c *conn) Close() error                        { return nil }
func (c *conn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

func (c *conn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	r := c.r
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, q)
	kid := args[0].Value.(string)
	switch {
	case strings.HasPrefix(q, "INSERT") && strings.Contains(q, "WHERE NOT EXISTS"):
		if len(r.rows) == 0 {
			r.rows[kid] = [3]any{[]byte(args[1].Value.(string)), args[2].Value, args[3].Value}
		}
	case strings.HasPrefix(q, "INSERT"):
		if _, ok := r.rows[kid]; !ok {
			r.rows[kid] = [3]any{[]byte(args[1].Value.(string)), args[2].Value, args[3].Value}
		}
	case strings.HasPrefix(q, "UPDATE"):
		if row, ok := r.rows[kid]; ok {
			row[1] = args[1].Value
			r.rows[kid] = row
		}
	case strings.HasPrefix(q, "DELETE"):
		delete(r.rows, kid)
	}
	return driver.RowsAffected(1), nil
}

func (c *conn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	r := c.r
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, q)
	out := &rows{}
	for kid, row := range r.rows {
		at, _ := time.Parse(time.RFC3339Nano, row[2].(string))
		out.data = append(out.data, []driver.Value{kid, row[0], row[1], at})
	}
	return out, nil
}

type rows struct {
	data [][]driver.Value
	i    int
}

func (r *rows) Columns() []string { return []string{"kid", "public_jwk", "sealed", "created_at"} }
func (r *rows) Close() error      { return nil }
func (r *rows) Next(dest []driver.Value) error {
	if r.i >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.i])
	r.i++
	return nil
}

var registerOnce sync.Once

func TestPostgresStore(t *testing.T) {
	rec := &recorder{rows: map[string][3]any{}}
	registerOnce.Do(func() { sql.Register("cauthy-keys-recorder", rec) })
	db, err := sql.Open("cauthy-keys-recorder", "")
	if err != nil {
		t.Fatal(err)
	}
	behaves(t, Postgres(db))
	for _, q := range rec.sent {
		if !strings.Contains(q, "cauthy_pact_keys") {
			t.Fatalf("a statement not on the table: %s", q)
		}
	}
	if _, err := PostgresTable(db, "keys; DROP TABLE users"); err == nil {
		t.Fatal("an unsafe table name must be refused")
	}
	ddl, err := TableSQL(DefaultTable)
	if err != nil || !strings.Contains(ddl, "public_jwk JSONB") || !strings.Contains(ddl, "created_at TIMESTAMPTZ") {
		t.Fatalf("%s %v", ddl, err)
	}
}
