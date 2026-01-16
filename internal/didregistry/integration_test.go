package didregistry_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"greything/internal/crypto"
	"greything/internal/didregistry"
	"greything/internal/store"
	"greything/internal/types"
)

func TestDidRegistry_CreateUser_AndResolveDidDoc(t *testing.T) {
	// Arrange: start in-memory server
	st := store.NewMemoryStore()
	ts := httptest.NewServer(didregistry.NewHandler(st, "greything.com", "http://example.test"))
	defer ts.Close()

	// Generate a real pubkey and encode to multibase
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	mb := "z" + callBase58EncodeForTest(pub)

	// Create user
	reqBody, _ := json.Marshal(types.CreateUserRequest{
		Username:               "anton",
		RootPublicKeyMultibase: mb,
	})
	resp, err := http.Post(ts.URL+"/v1/users", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /v1/users: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST status = %d, want 200", resp.StatusCode)
	}

	var created types.CreateUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create resp: %v", err)
	}
	if created.DID != "did:web:greything.com:users:anton" {
		t.Fatalf("DID = %q", created.DID)
	}

	// Resolve did.json
	getResp, err := http.Get(ts.URL + "/users/anton/did.json")
	if err != nil {
		t.Fatalf("GET did.json: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != 200 {
		t.Fatalf("GET status = %d, want 200", getResp.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode did.json: %v", err)
	}

	// Validate: id present
	if doc["id"] != "did:web:greything.com:users:anton" {
		t.Fatalf("doc.id = %#v", doc["id"])
	}

	// Validate: verificationMethod contains #root with correct pubkey multibase
	vms, ok := doc["verificationMethod"].([]any)
	if !ok || len(vms) == 0 {
		t.Fatalf("verificationMethod missing/empty")
	}

	foundRoot := false
	for _, item := range vms {
		m, _ := item.(map[string]any)
		if m["id"] == "did:web:greything.com:users:anton#root" {
			foundRoot = true
			if m["publicKeyMultibase"] != mb {
				t.Fatalf("root pubkey mb mismatch: got %v want %v", m["publicKeyMultibase"], mb)
			}
		}
	}
	if !foundRoot {
		t.Fatalf("root verification method not found")
	}

	// And ensure our multibase decoder can parse it
	_, derr := crypto.DecodeMultibaseEd25519Pub(mb)
	if derr != nil {
		t.Fatalf("DecodeMultibaseEd25519Pub failed: %v", derr)
	}
}

// We keep base58Encode unexported, so we use a tiny helper for tests.
// Option A: export it (Base58Encode) later.
// Option B: re-encode by decoding + encoding isn't possible. We'll add an exported helper below.
// For now, implement the same encode logic inline to keep the test self-contained.
func callBase58EncodeForTest(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	digits := []int{0}
	for _, v := range b {
		carry := int(v)
		for j := 0; j < len(digits); j++ {
			carry += digits[j] << 8
			digits[j] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, carry%58)
			carry /= 58
		}
	}
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	out := make([]byte, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out[i] = '1'
	}
	for i := 0; i < len(digits); i++ {
		out[len(out)-1-i] = alphabet[digits[i]]
	}
	return string(out)
}
