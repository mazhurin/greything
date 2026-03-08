package dids

import (
	"crypto/ed25519"
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

	gcrypto "greything/internal/crypto"
)

// mockStorageServer creates a test HTTP server that mimics gt-core for claims head/blob.
func mockStorageServer(t *testing.T, didStr string, manifest *ClaimsManifest) *httptest.Server {
	t.Helper()

	var headHash string
	var blobData []byte

	if manifest != nil {
		blobData, _ = json.Marshal(manifest)
		h := sha256.Sum256(blobData)
		headHash = "sha256-" + hex.EncodeToString(h[:])
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if manifest == nil {
			http.NotFound(w, r)
			return
		}

		headPath := fmt.Sprintf("/gt/v1/%s/heads/claims", didStr)
		hexHash := strings.TrimPrefix(headHash, "sha256-")
		blobPath := fmt.Sprintf("/gt/v1/%s/blobs/sha256/%s", didStr, hexHash)

		switch r.URL.Path {
		case headPath:
			json.NewEncoder(w).Encode(map[string]string{"head": headHash})
		case blobPath:
			w.Write(blobData)
		default:
			http.NotFound(w, r)
		}
	}))
}

func makeTestServerWithStorage(t *testing.T, storageURL string) *Server {
	t.Helper()
	dir := t.TempDir()
	return &Server{
		Domain:     "did.greything.com",
		DocRoot:    dir,
		StorageURL: storageURL,
	}
}

// setupUserDID creates a did.json on disk so authenticate() can find the root key.
func setupUserDID(t *testing.T, srv *Server, id string, pub ed25519.PublicKey) string {
	t.Helper()
	didStr := fmt.Sprintf("did:web:%s:u:%s", srv.Domain, id)
	doc := makeDIDDoc(didStr, pub)
	data, _ := json.Marshal(doc)

	dir := filepath.Join(srv.DocRoot, "u", id)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "did.json"), data, 0o644)

	return didStr
}

func doReindex(t *testing.T, srv *Server, id, didStr string, priv ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/v1/did/" + id + "/reindex"
	body := []byte{}
	ts, sig, authDID := signRequest(http.MethodPost, path, body, didStr, priv)

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("X-GT-DID", authDID)
	req.Header.Set("X-GT-Timestamp", ts)
	req.Header.Set("X-GT-Signature", sig)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func writeClaimsIndex(t *testing.T, srv *Server, id string, index ClaimsIndex) {
	t.Helper()
	dir := filepath.Join(srv.DocRoot, "u", id)
	os.MkdirAll(dir, 0o755)
	data, _ := json.Marshal(index)
	os.WriteFile(filepath.Join(dir, "claims-index.json"), data, 0o644)
}

func TestReindex(t *testing.T) {
	pub, priv := generateKey(t)
	userID := "testuser"

	manifest := &ClaimsManifest{
		Version:   1,
		DID:       "did:web:did.greything.com:u:" + userID,
		Claims:    map[string]string{"name": "Almaz", "city": "Kazan"},
		CreatedAt: "2026-02-19T12:00:00Z",
	}
	storage := mockStorageServer(t, manifest.DID, manifest)
	defer storage.Close()

	srv := makeTestServerWithStorage(t, storage.URL)
	didStr := setupUserDID(t, srv, userID, pub)

	w := doReindex(t, srv, userID, didStr, priv)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify index file was written
	data, err := os.ReadFile(filepath.Join(srv.DocRoot, "u", userID, "claims-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index ClaimsIndex
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	if index.DID != didStr {
		t.Fatalf("index DID = %q, want %q", index.DID, didStr)
	}
	if index.Claims["name"] != "Almaz" {
		t.Fatalf("index name = %q, want Almaz", index.Claims["name"])
	}
	if index.Claims["city"] != "Kazan" {
		t.Fatalf("index city = %q, want Kazan", index.Claims["city"])
	}
}

func TestSearch(t *testing.T) {
	srv := makeTestServerWithStorage(t, "")

	// Set up two users with claims indexes
	pub1, _ := generateKey(t)
	pub2, _ := generateKey(t)
	setupUserDID(t, srv, "user1", pub1)
	setupUserDID(t, srv, "user2", pub2)

	writeClaimsIndex(t, srv, "user1", ClaimsIndex{
		DID:    "did:web:did.greything.com:u:user1",
		Claims: map[string]string{"name": "Almaz", "city": "Kazan"},
	})
	writeClaimsIndex(t, srv, "user2", ClaimsIndex{
		DID:    "did:web:did.greything.com:u:user2",
		Claims: map[string]string{"name": "Bob", "city": "Moscow"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=Almaz", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var results []ClaimsSearchResult
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].DID != "did:web:did.greything.com:u:user1" {
		t.Fatalf("wrong DID: %s", results[0].DID)
	}
}

func TestSearchCaseInsensitive(t *testing.T) {
	srv := makeTestServerWithStorage(t, "")

	pub, _ := generateKey(t)
	setupUserDID(t, srv, "user1", pub)
	writeClaimsIndex(t, srv, "user1", ClaimsIndex{
		DID:    "did:web:did.greything.com:u:user1",
		Claims: map[string]string{"name": "Almaz", "city": "Kazan"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=almaz", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var results []ClaimsSearchResult
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 result for case-insensitive search, got %d", len(results))
	}
}

func TestLookupExact(t *testing.T) {
	srv := makeTestServerWithStorage(t, "")

	pub1, _ := generateKey(t)
	pub2, _ := generateKey(t)
	setupUserDID(t, srv, "user1", pub1)
	setupUserDID(t, srv, "user2", pub2)

	writeClaimsIndex(t, srv, "user1", ClaimsIndex{
		DID:    "did:web:did.greything.com:u:user1",
		Claims: map[string]string{"phone_hash": "sha256-abc123", "name": "Almaz"},
	})
	writeClaimsIndex(t, srv, "user2", ClaimsIndex{
		DID:    "did:web:did.greything.com:u:user2",
		Claims: map[string]string{"phone_hash": "sha256-def456", "name": "Bob"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/lookup?key=phone_hash&value=sha256-abc123", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var results []ClaimsSearchResult
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].DID != "did:web:did.greything.com:u:user1" {
		t.Fatalf("wrong DID: %s", results[0].DID)
	}
}

func TestLookupNoPartialMatch(t *testing.T) {
	srv := makeTestServerWithStorage(t, "")

	pub, _ := generateKey(t)
	setupUserDID(t, srv, "user1", pub)
	writeClaimsIndex(t, srv, "user1", ClaimsIndex{
		DID:    "did:web:did.greything.com:u:user1",
		Claims: map[string]string{"phone_hash": "sha256-abc123"},
	})

	// Partial value should NOT match lookup (exact match only)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/lookup?key=phone_hash&value=sha256-abc", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var results []ClaimsSearchResult
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 0 {
		t.Fatalf("expected 0 results for partial match, got %d", len(results))
	}
}

func TestReindexBadAuth(t *testing.T) {
	pub, _ := generateKey(t)
	_, wrongPriv := generateKey(t)
	userID := "testuser"

	manifest := &ClaimsManifest{
		Version:   1,
		DID:       "did:web:did.greything.com:u:" + userID,
		Claims:    map[string]string{"name": "Almaz"},
		CreatedAt: "2026-02-19T12:00:00Z",
	}
	storage := mockStorageServer(t, manifest.DID, manifest)
	defer storage.Close()

	srv := makeTestServerWithStorage(t, storage.URL)
	didStr := setupUserDID(t, srv, userID, pub)

	// Use wrong private key
	w := doReindex(t, srv, userID, didStr, wrongPriv)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// Verify no index file was written
	_, err := os.ReadFile(filepath.Join(srv.DocRoot, "u", userID, "claims-index.json"))
	if err == nil {
		t.Fatal("index file should not exist after bad auth")
	}
}

// TestSearchSkipsHashFields verifies that _hash fields are not included in full-text search.
func TestSearchSkipsHashFields(t *testing.T) {
	srv := makeTestServerWithStorage(t, "")

	pub, _ := generateKey(t)
	setupUserDID(t, srv, "user1", pub)
	writeClaimsIndex(t, srv, "user1", ClaimsIndex{
		DID:    "did:web:did.greything.com:u:user1",
		Claims: map[string]string{"phone_hash": "sha256-abc123", "name": "Almaz"},
	})

	// Search for the hash value — should NOT find it via full-text search
	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=abc123", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var results []ClaimsSearchResult
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 0 {
		t.Fatalf("expected 0 results (hash fields should be skipped in search), got %d", len(results))
	}
}

// Ensure unused imports don't cause errors
var _ = gcrypto.Base58Encode
