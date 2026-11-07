// Package pgtest runs the key stores against a real Postgres. It is its own
// module, so the driver it needs never reaches the core module, which has no
// dependency. Without CAUTHY_TEST_POSTGRES_DSN every test is skipped.
//
//	CAUTHY_TEST_POSTGRES_DSN=postgres://user:pass@localhost:5432/db?sslmode=disable go test ./...
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/vennet-developers/cauthy-sdk-go/internal/storetest"
	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

// open answers a database and a table of its own, made with TableSQL and
// dropped when the test ends, so runs never meet each other's keys.
func open(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("CAUTHY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CAUTHY_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	suffix := make([]byte, 6)
	rand.Read(suffix)
	table := "cauthy_pact_keys_test_" + hex.EncodeToString(suffix)
	ddl, err := keys.TableSQL(table)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+table) })
	return db, table
}

func TestPostgresStoreOnARealPostgres(t *testing.T) {
	db, table := open(t)
	s, err := keys.PostgresTable(db, table)
	if err != nil {
		t.Fatal(err)
	}
	storetest.Behaves(t, s)
}

// Instances starting together each try AddFirst with a key of their own: one
// key, and only one, is kept.
func TestAddFirstKeepsOneKeyUnderARace(t *testing.T) {
	db, table := open(t)
	db.SetMaxOpenConns(16)
	s, err := keys.PostgresTable(db, table)
	if err != nil {
		t.Fatal(err)
	}
	for round := range 20 {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range 12 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				k := keys.StoredKey{Kid: fmt.Sprintf("k-%d-%d", round, i), PublicJWK: map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"},
					Sealed: "sealed", CreatedAt: "2026-01-01T00:00:00.000Z"}
				if err := s.AddFirst(context.Background(), k); err != nil {
					t.Error(err)
				}
			}()
		}
		close(start)
		wg.Wait()
		list, err := s.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 1 {
			t.Fatalf("round %d: %d keys kept, want 1", round, len(list))
		}
	}
}
