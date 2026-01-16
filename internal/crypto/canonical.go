package crypto

import (
	"fmt"
	"strings"

	"greything/internal/types"
)

func CanonicalPost(p types.Post) string {
	// Keep it super stable: no JSON canonicalization yet.
	// Use RFC3339 for time, no extra spaces, fixed separators.
	return strings.Join([]string{
		"Post",
		p.Author,
		p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		p.Content,
	}, "|")
}

func CanonicalEvent(e types.Event) string {
	return strings.Join([]string{
		"Event",
		e.Type,
		e.Actor,
		e.ObjectURL,
		e.TS.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}, "|")
}

func MustAlgEd25519(alg string) error {
	if alg != "Ed25519" {
		return fmt.Errorf("unsupported alg: %s", alg)
	}
	return nil
}
