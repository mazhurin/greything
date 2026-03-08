package dids

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gcrypto "greything/internal/crypto"
	"greything/internal/did"
)

func makeTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	return &Server{
		Domain:  "did.greything.com",
		DocRoot: dir,
	}
}

func generateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func makeDIDDoc(didStr string, pub ed25519.PublicKey, extraVMs ...did.VerificationMethod) did.DIDDocument {
	mb := "z" + gcrypto.Base58Encode(pub)
	vms := []did.VerificationMethod{
		{
			ID:                 didStr + "#root",
			Type:               "Ed25519VerificationKey2020",
			Controller:         didStr,
			PublicKeyMultibase: mb,
		},
	}
	vms = append(vms, extraVMs...)
	return did.DIDDocument{
		Context:            []string{"https://www.w3.org/ns/did/v1"},
		ID:                 didStr,
		VerificationMethod: vms,
		Authentication:     []string{didStr + "#root"},
		AssertionMethod:    []string{didStr + "#root"},
		CapabilityInv:      []string{didStr + "#root"},
		CapabilityDel:      []string{didStr + "#root"},
		Service:            []did.Service{},
	}
}

func signRequest(method, path string, body []byte, didStr string, priv ed25519.PrivateKey) (string, string, string) {
	ts := time.Now().UTC().Format(time.RFC3339)
	h := sha256.Sum256(body)
	bodyHash := "sha256-" + hex.EncodeToString(h[:])
	payload := fmt.Sprintf("%s|%s|%s|%s", ts, method, path, bodyHash)
	sig := gcrypto.SignEd25519(priv, payload)
	return ts, sig, didStr
}

func doPut(t *testing.T, srv *Server, id string, body []byte, didStr string, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/v1/did/" + id
	ts, sig, authDID := signRequest(http.MethodPut, path, body, didStr, priv)

	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(string(body)))
	req.Header.Set("X-GT-DID", authDID)
	req.Header.Set("X-GT-Timestamp", ts)
	req.Header.Set("X-GT-Signature", sig)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestPutNewDID(t *testing.T) {
	srv := makeTestServer(t)
	pub, priv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"
	doc := makeDIDDoc(didStr, pub)
	body, _ := json.Marshal(doc)

	w := doPut(t, srv, "testuser", body, didStr, priv)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify file was written
	data, err := os.ReadFile(filepath.Join(srv.DocRoot, "u", "testuser", "did.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved did.DIDDocument
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.ID != didStr {
		t.Fatalf("saved doc ID = %q, want %q", saved.ID, didStr)
	}
}

func TestPutUpdateDID(t *testing.T) {
	srv := makeTestServer(t)
	pub, priv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	// Create initial
	doc := makeDIDDoc(didStr, pub)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, priv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Update: add a device key
	devicePub, _ := generateKey(t)
	deviceMB := "z" + gcrypto.Base58Encode(devicePub)
	doc.VerificationMethod = append(doc.VerificationMethod, did.VerificationMethod{
		ID:                 didStr + "#device-1",
		Type:               "Ed25519VerificationKey2020",
		Controller:         didStr,
		PublicKeyMultibase: deviceMB,
	})
	body2, _ := json.Marshal(doc)
	w2 := doPut(t, srv, "testuser", body2, didStr, priv)
	if w2.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify updated file
	data, _ := os.ReadFile(filepath.Join(srv.DocRoot, "u", "testuser", "did.json"))
	var saved did.DIDDocument
	json.Unmarshal(data, &saved)
	if len(saved.VerificationMethod) != 2 {
		t.Fatalf("expected 2 VMs, got %d", len(saved.VerificationMethod))
	}
}

func TestPutBadAuth(t *testing.T) {
	srv := makeTestServer(t)
	pub, _ := generateKey(t)
	_, wrongPriv := generateKey(t) // different key
	didStr := "did:web:did.greything.com:u:testuser"
	doc := makeDIDDoc(didStr, pub)
	body, _ := json.Marshal(doc)

	w := doPut(t, srv, "testuser", body, didStr, wrongPriv)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPutWrongDID(t *testing.T) {
	srv := makeTestServer(t)
	_, priv := generateKey(t)
	// Auth as a different DID than the URL
	wrongDID := "did:web:did.greything.com:u:otheruser"
	path := "/api/v1/did/testuser"
	body := []byte(`{}`)
	ts, sig, _ := signRequest(http.MethodPut, path, body, wrongDID, priv)

	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(string(body)))
	req.Header.Set("X-GT-DID", wrongDID)
	req.Header.Set("X-GT-Timestamp", ts)
	req.Header.Set("X-GT-Signature", sig)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPutInvalidDoc(t *testing.T) {
	srv := makeTestServer(t)
	pub, priv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"
	// Doc ID doesn't match URL
	doc := makeDIDDoc("did:web:did.greything.com:u:wrongid", pub)
	body, _ := json.Marshal(doc)

	w := doPut(t, srv, "testuser", body, didStr, priv)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPutPreservesRootKey(t *testing.T) {
	srv := makeTestServer(t)
	pub, priv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	// Create with root key
	doc := makeDIDDoc(didStr, pub)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, priv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d", w.Code)
	}

	// Try to update with a different root key — should fail (signed by old key, but new doc has different root)
	// Actually the attack is: someone who has the current root key tries to replace it
	// The real test: update with empty VMs → should fail
	badDoc := did.DIDDocument{
		Context:            []string{"https://www.w3.org/ns/did/v1"},
		ID:                 didStr,
		VerificationMethod: []did.VerificationMethod{},
		Service:            []did.Service{},
	}
	body2, _ := json.Marshal(badDoc)
	w2 := doPut(t, srv, "testuser", body2, didStr, priv)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty VMs, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestDeviceKeyCanUpdateDID(t *testing.T) {
	srv := makeTestServer(t)
	rootPub, rootPriv := generateKey(t)
	devicePub, devicePriv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	// Create DID with root + device key
	rootMB := "z" + gcrypto.Base58Encode(rootPub)
	deviceMB := "z" + gcrypto.Base58Encode(devicePub)
	doc := did.Build(didStr, rootMB, nil, map[string]string{"device-1": deviceMB}, nil, nil)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, rootPriv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Device key adds another device key
	newDevPub, _ := generateKey(t)
	newDevMB := "z" + gcrypto.Base58Encode(newDevPub)
	doc2 := did.Build(didStr, rootMB, nil, map[string]string{
		"device-1": deviceMB,
		"device-2": newDevMB,
	}, nil, nil)
	body2, _ := json.Marshal(doc2)
	w2 := doPut(t, srv, "testuser", body2, didStr, devicePriv)
	if w2.Code != http.StatusOK {
		t.Fatalf("device key update: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify the update was saved
	data, _ := os.ReadFile(filepath.Join(srv.DocRoot, "u", "testuser", "did.json"))
	var saved did.DIDDocument
	json.Unmarshal(data, &saved)
	if len(saved.VerificationMethod) != 3 {
		t.Fatalf("expected 3 VMs, got %d", len(saved.VerificationMethod))
	}
}

func TestDeviceKeyCannotChangeRootKey(t *testing.T) {
	srv := makeTestServer(t)
	rootPub, rootPriv := generateKey(t)
	devicePub, devicePriv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	// Create DID with root + device key
	rootMB := "z" + gcrypto.Base58Encode(rootPub)
	deviceMB := "z" + gcrypto.Base58Encode(devicePub)
	doc := did.Build(didStr, rootMB, nil, map[string]string{"device-1": deviceMB}, nil, nil)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, rootPriv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Device key tries to change root key → should be 403
	newRootPub, _ := generateKey(t)
	newRootMB := "z" + gcrypto.Base58Encode(newRootPub)
	doc2 := did.Build(didStr, newRootMB, nil, map[string]string{"device-1": deviceMB}, nil, nil)
	body2, _ := json.Marshal(doc2)
	w2 := doPut(t, srv, "testuser", body2, didStr, devicePriv)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestRootKeyCanChangeAnything(t *testing.T) {
	srv := makeTestServer(t)
	rootPub, rootPriv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	// Create DID
	rootMB := "z" + gcrypto.Base58Encode(rootPub)
	doc := did.Build(didStr, rootMB, nil, nil, nil, nil)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, rootPriv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Root key rotates itself (new root key)
	newRootPub, newRootPriv := generateKey(t)
	newRootMB := "z" + gcrypto.Base58Encode(newRootPub)
	doc2 := did.Build(didStr, newRootMB, nil, nil, nil, nil)
	body2, _ := json.Marshal(doc2)
	// Signed by old root key
	w2 := doPut(t, srv, "testuser", body2, didStr, rootPriv)
	if w2.Code != http.StatusOK {
		t.Fatalf("root key rotation: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify new root key works
	devPub, _ := generateKey(t)
	devMB := "z" + gcrypto.Base58Encode(devPub)
	doc3 := did.Build(didStr, newRootMB, nil, map[string]string{"device-1": devMB}, nil, nil)
	body3, _ := json.Marshal(doc3)
	w3 := doPut(t, srv, "testuser", body3, didStr, newRootPriv)
	if w3.Code != http.StatusOK {
		t.Fatalf("update with new root: expected 200, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestDeviceKeyCannotAddRecoveryPolicy(t *testing.T) {
	srv := makeTestServer(t)
	rootPub, rootPriv := generateKey(t)
	devicePub, devicePriv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	rootMB := "z" + gcrypto.Base58Encode(rootPub)
	deviceMB := "z" + gcrypto.Base58Encode(devicePub)

	// Create DID without recovery policy
	doc := did.Build(didStr, rootMB, nil, map[string]string{"device-1": deviceMB}, nil, nil)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, rootPriv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Device key tries to add recovery policy → 403
	policy := &did.RecoveryPolicy{
		Type:        "PassphraseEncryptedKey",
		StorageHead: "recovery-key",
		SetAt:       "2026-02-23T10:00:00Z",
	}
	doc2 := did.Build(didStr, rootMB, nil, map[string]string{"device-1": deviceMB}, nil, policy)
	body2, _ := json.Marshal(doc2)
	w2 := doPut(t, srv, "testuser", body2, didStr, devicePriv)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestDeviceKeyCannotRemoveRecoveryPolicy(t *testing.T) {
	srv := makeTestServer(t)
	rootPub, rootPriv := generateKey(t)
	devicePub, devicePriv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	rootMB := "z" + gcrypto.Base58Encode(rootPub)
	deviceMB := "z" + gcrypto.Base58Encode(devicePub)

	// Create DID with recovery policy
	policy := &did.RecoveryPolicy{
		Type:        "PassphraseEncryptedKey",
		StorageHead: "recovery-key",
		SetAt:       "2026-02-23T10:00:00Z",
	}
	doc := did.Build(didStr, rootMB, nil, map[string]string{"device-1": deviceMB}, nil, policy)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, rootPriv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Device key tries to remove recovery policy → 403
	doc2 := did.Build(didStr, rootMB, nil, map[string]string{"device-1": deviceMB}, nil, nil)
	body2, _ := json.Marshal(doc2)
	w2 := doPut(t, srv, "testuser", body2, didStr, devicePriv)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestRootKeyCanSetRecoveryPolicy(t *testing.T) {
	srv := makeTestServer(t)
	rootPub, rootPriv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	rootMB := "z" + gcrypto.Base58Encode(rootPub)

	// Create DID without recovery policy
	doc := did.Build(didStr, rootMB, nil, nil, nil, nil)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, rootPriv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Root key sets recovery policy → 200
	policy := &did.RecoveryPolicy{
		Type:        "PassphraseEncryptedKey",
		StorageHead: "recovery-key",
		SetAt:       "2026-02-23T10:00:00Z",
	}
	doc2 := did.Build(didStr, rootMB, nil, nil, nil, policy)
	body2, _ := json.Marshal(doc2)
	w2 := doPut(t, srv, "testuser", body2, didStr, rootPriv)
	if w2.Code != http.StatusOK {
		t.Fatalf("set recovery policy: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestDeviceKeyPreservesRecoveryPolicy(t *testing.T) {
	srv := makeTestServer(t)
	rootPub, rootPriv := generateKey(t)
	devicePub, devicePriv := generateKey(t)
	didStr := "did:web:did.greything.com:u:testuser"

	rootMB := "z" + gcrypto.Base58Encode(rootPub)
	deviceMB := "z" + gcrypto.Base58Encode(devicePub)

	// Create DID with recovery policy and device key
	policy := &did.RecoveryPolicy{
		Type:        "PassphraseEncryptedKey",
		StorageHead: "recovery-key",
		SetAt:       "2026-02-23T10:00:00Z",
	}
	doc := did.Build(didStr, rootMB, nil, map[string]string{"device-1": deviceMB}, nil, policy)
	body, _ := json.Marshal(doc)
	w := doPut(t, srv, "testuser", body, didStr, rootPriv)
	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Device key adds another device key, preserving recovery policy → 200
	newDevPub, _ := generateKey(t)
	newDevMB := "z" + gcrypto.Base58Encode(newDevPub)
	doc2 := did.Build(didStr, rootMB, nil, map[string]string{
		"device-1": deviceMB,
		"device-2": newDevMB,
	}, nil, policy)
	body2, _ := json.Marshal(doc2)
	w2 := doPut(t, srv, "testuser", body2, didStr, devicePriv)
	if w2.Code != http.StatusOK {
		t.Fatalf("device key update preserving policy: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}
