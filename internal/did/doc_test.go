package did

import (
	"encoding/json"
	"testing"
)

func TestParseDocumentRoundTrip(t *testing.T) {
	didStr := "did:web:did.greything.com:u:testuser"
	rootPub := "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	services := map[string]string{
		"pod":     "https://storage.greything.com/gt/v1/" + didStr,
		"profile": "https://greything.com/u/testuser",
		"events":  "https://events.greything.com/v1/" + didStr,
	}
	deviceKeys := map[string]string{
		"device-1": "z6MkpTHR8VNs5zPcZTS7R4xTGZXHbHFuRQrgGPAic8iWpA9D",
		"laptop":   "z6Mki8TRRYcVqWALFvZx2GhFfbEo1kuX4aCkz3HGp8HUU5qM",
	}
	deviceXKeys := map[string]string{
		"x25519-1": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
	}

	// Build → ParseDocument → Build → compare JSON
	doc1 := Build(didStr, rootPub, services, deviceKeys, deviceXKeys, nil)

	parsedRoot, parsedSvc, parsedDev, parsedXDev, parsedPolicy := ParseDocument(doc1)

	if parsedRoot != rootPub {
		t.Fatalf("rootPub mismatch: got %q, want %q", parsedRoot, rootPub)
	}
	for k, v := range services {
		if parsedSvc[k] != v {
			t.Fatalf("service %q: got %q, want %q", k, parsedSvc[k], v)
		}
	}
	for k, v := range deviceKeys {
		if parsedDev[k] != v {
			t.Fatalf("deviceKey %q: got %q, want %q", k, parsedDev[k], v)
		}
	}
	for k, v := range deviceXKeys {
		if parsedXDev[k] != v {
			t.Fatalf("deviceXKey %q: got %q, want %q", k, parsedXDev[k], v)
		}
	}
	if parsedPolicy != nil {
		t.Fatal("expected nil recovery policy")
	}

	doc2 := Build(didStr, parsedRoot, parsedSvc, parsedDev, parsedXDev, parsedPolicy)

	j1, _ := json.Marshal(doc1)
	j2, _ := json.Marshal(doc2)

	if string(j1) != string(j2) {
		t.Fatalf("round-trip mismatch:\n  doc1: %s\n  doc2: %s", j1, j2)
	}
}

func TestParseDocumentEmpty(t *testing.T) {
	didStr := "did:web:did.greything.com:u:empty"
	rootPub := "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	doc := Build(didStr, rootPub, nil, nil, nil, nil)
	parsedRoot, parsedSvc, parsedDev, parsedXDev, _ := ParseDocument(doc)

	if parsedRoot != rootPub {
		t.Fatalf("rootPub: got %q, want %q", parsedRoot, rootPub)
	}
	if len(parsedDev) != 0 {
		t.Fatalf("expected no device keys, got %d", len(parsedDev))
	}
	if len(parsedXDev) != 0 {
		t.Fatalf("expected no x25519 keys, got %d", len(parsedXDev))
	}
	if len(parsedSvc) != 0 {
		t.Fatalf("expected no services, got %d", len(parsedSvc))
	}
}

func TestRecoveryPolicyRoundTrip(t *testing.T) {
	didStr := "did:web:did.greything.com:u:recovery"
	rootPub := "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	policy := &RecoveryPolicy{
		Type:        "PassphraseEncryptedKey",
		StorageHead: "recovery-key",
		SetAt:       "2026-02-23T10:00:00Z",
	}

	doc1 := Build(didStr, rootPub, nil, nil, nil, policy)
	j1, _ := json.Marshal(doc1)

	parsedRoot, parsedSvc, parsedDev, parsedXDev, parsedPolicy := ParseDocument(doc1)

	if parsedPolicy == nil {
		t.Fatal("expected non-nil recovery policy")
	}
	if parsedPolicy.Type != policy.Type {
		t.Fatalf("policy type: got %q, want %q", parsedPolicy.Type, policy.Type)
	}
	if parsedPolicy.StorageHead != policy.StorageHead {
		t.Fatalf("policy storageHead: got %q, want %q", parsedPolicy.StorageHead, policy.StorageHead)
	}
	if parsedPolicy.SetAt != policy.SetAt {
		t.Fatalf("policy setAt: got %q, want %q", parsedPolicy.SetAt, policy.SetAt)
	}

	doc2 := Build(didStr, parsedRoot, parsedSvc, parsedDev, parsedXDev, parsedPolicy)
	j2, _ := json.Marshal(doc2)

	if string(j1) != string(j2) {
		t.Fatalf("round-trip mismatch:\n  doc1: %s\n  doc2: %s", j1, j2)
	}
}
