package keys_test

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

	"github.com/vennet-developers/cauthy-sdk-go/internal/storetest"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

// recorder is a database/sql driver that keeps a key table in memory and
// understands exactly the five statements the store sends, so the test sees
// the SQL itself. internal/pgtest runs the same behaviour on a real Postgres
// (CI's postgres job).
type recorder struct {
	mu   sync.Mutex
	rows map[string][3]any // kid → public_jwk, sealed, created_at
	sent []string
	txs  []string // BEGIN, COMMIT and ROLLBACK, in order, with what ran inside
	inTx bool
}

func (r *recorder) Open(string) (driver.Conn, error) { return &conn{r}, nil }

// Connect and Driver make the recorder a driver.Connector, so each test opens
// its own with sql.OpenDB instead of registering one recorder for the process.
func (r *recorder) Connect(context.Context) (driver.Conn, error) { return &conn{r}, nil }
func (r *recorder) Driver() driver.Driver                        { return r }

type conn struct{ r *recorder }

func (c *conn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no prepare") }
func (c *conn) Close() error                        { return nil }
func (c *conn) Begin() (driver.Tx, error) {
	c.r.mu.Lock()
	defer c.r.mu.Unlock()
	c.r.txs, c.r.inTx = append(c.r.txs, "BEGIN"), true
	return tx{c.r}, nil
}

type tx struct{ r *recorder }

func (t tx) Commit() error   { return t.end("COMMIT") }
func (t tx) Rollback() error { return t.end("ROLLBACK") }
func (t tx) end(word string) error {
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	t.r.txs, t.r.inTx = append(t.r.txs, word), false
	return nil
}

func (c *conn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	r := c.r
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, q)
	if r.inTx {
		r.txs = append(r.txs, q)
	}
	if len(args) == 0 {
		return driver.RowsAffected(0), nil
	}
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

func TestPostgresStore(t *testing.T) {
	rec := &recorder{rows: map[string][3]any{}}
	db := sql.OpenDB(rec)
	defer db.Close()
	storetest.Behaves(t, keys.Postgres(db))
	for _, q := range rec.sent {
		if !strings.Contains(q, "cauthy_pact_keys") {
			t.Fatalf("a statement not on the table: %s", q)
		}
	}
	// Behaves calls AddFirst twice: each one is its own transaction.
	if len(rec.txs) != 8 {
		t.Fatalf("AddFirst must insert in a transaction under the table's advisory lock: %q", rec.txs)
	}
	for i := 0; i < 8; i += 4 {
		if rec.txs[i] != "BEGIN" || rec.txs[i+1] != "SELECT pg_advisory_xact_lock(hashtext('cauthy_pact_keys'))" ||
			!strings.Contains(rec.txs[i+2], "WHERE NOT EXISTS") || rec.txs[i+3] != "COMMIT" {
			t.Fatalf("AddFirst must insert in a transaction under the table's advisory lock: %q", rec.txs)
		}
	}
	if _, err := keys.PostgresTable(db, "keys; DROP TABLE users"); err == nil {
		t.Fatal("an unsafe table name must be refused")
	}
	ddl, err := keys.TableSQL(keys.DefaultTable)
	if err != nil || !strings.Contains(ddl, "public_jwk JSONB") || !strings.Contains(ddl, "created_at TIMESTAMPTZ") {
		t.Fatalf("%s %v", ddl, err)
	}
}
