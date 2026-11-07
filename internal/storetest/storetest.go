// Package storetest is the behaviour every key store must show, shared by the
// keys package's tests and the real-Postgres tests of internal/pgtest.
package storetest

import (
	"context"
	"slices"
	"testing"

	"github.com/vennet-developers/cauthy-sdk-go/keys"
)

func storedKey(kid, at string) keys.StoredKey {
	return keys.StoredKey{Kid: kid, PublicJWK: map[string]any{"kty": "RSA", "n": "AQAB", "e": "AQAB"}, Sealed: "sealed-" + kid, CreatedAt: at}
}

func kids(t *testing.T, s keys.Store) []string {
	t.Helper()
	list, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range list {
		out = append(out, k.Kid+":"+k.Sealed)
	}
	slices.Sort(out)
	return out
}

// Behaves is what every keys.Store must do: the memory, file and Postgres
// stores of package keys, and a real Postgres in the pgtest module.
func Behaves(t *testing.T, s keys.Store) {
	t.Helper()
	ctx := context.Background()
	if got := kids(t, s); len(got) != 0 {
		t.Fatalf("a new store holds %v", got)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.AddFirst(ctx, storedKey("a", "2026-01-01T00:00:00.000Z")))
	must(s.AddFirst(ctx, storedKey("b", "2026-01-01T00:00:01.000Z")))
	if got := kids(t, s); !slices.Equal(got, []string{"a:sealed-a"}) {
		t.Fatalf("AddFirst keeps only the first: %v", got)
	}
	must(s.Add(ctx, storedKey("b", "2026-01-02T00:00:00.000Z")))
	again := storedKey("a", "2026-01-01T00:00:00.000Z")
	again.Sealed = "other"
	must(s.Add(ctx, again))
	if got := kids(t, s); !slices.Equal(got, []string{"a:sealed-a", "b:sealed-b"}) {
		t.Fatalf("Add leaves a kept kid as it is: %v", got)
	}
	must(s.Update(ctx, again))
	must(s.Remove(ctx, "b"))
	if got := kids(t, s); !slices.Equal(got, []string{"a:other"}) {
		t.Fatalf("Update and Remove: %v", got)
	}
	list, _ := s.List(ctx)
	if list[0].CreatedAt != "2026-01-01T00:00:00.000Z" || list[0].PublicJWK["kty"] != "RSA" {
		t.Fatalf("round trip: %+v", list[0])
	}
}
