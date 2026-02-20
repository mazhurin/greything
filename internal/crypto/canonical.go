package crypto

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"greything/internal/types"
)

// CanonicalJSON returns a canonical JSON representation of a map.
// Keys are sorted, no extra whitespace.
func CanonicalJSON(data map[string]any) ([]byte, error) {
	return canonicalValue(data)
}

func canonicalValue(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		return canonicalObject(val)
	case []any:
		return canonicalArray(val)
	default:
		// For primitives, use standard JSON encoding
		return json.Marshal(v)
	}
}

func canonicalObject(m map[string]any) ([]byte, error) {
	// Sort keys
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf strings.Builder
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		// Key
		keyBytes, _ := json.Marshal(k)
		buf.Write(keyBytes)
		buf.WriteByte(':')
		// Value
		valBytes, err := canonicalValue(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

func canonicalArray(arr []any) ([]byte, error) {
	var buf strings.Builder
	buf.WriteByte('[')
	for i, v := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		valBytes, err := canonicalValue(v)
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}
	buf.WriteByte(']')
	return []byte(buf.String()), nil
}

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
