package gtcore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"greything/internal/crypto"
	"greything/internal/storage"
)

// --- Mock DID Resolver ---

type mockResolver struct {
	keys map[string][][]byte // DID → list of Ed25519 public keys
}

func (m *mockResolver) ResolveEd25519Keys(did string) ([][]byte, error) {
	keys, ok := m.keys[did]
	if !ok || len(keys) == 0 {
		return nil, fmt.Errorf("DID not found: %s", did)
	}
	return keys, nil
}

// --- Test helpers ---

func signRequest(t *testing.T, priv ed25519.PrivateKey, did, method, path string, body []byte) (timestamp, signature string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	h := sha256.Sum256(body)
	bodyHash := "sha256-" + hex.EncodeToString(h[:])
	payload := fmt.Sprintf("%s|%s|%s|%s", ts, method, path, bodyHash)
	sig := crypto.SignEd25519(priv, payload)
	return ts, sig
}

func setupTest(t *testing.T) (*httptest.Server, ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	did := "did:web:example.com:u:alice"

	resolver := &mockResolver{
		keys: map[string][][]byte{
			did: {[]byte(pub)},
		},
	}

	adapter, err := storage.NewFilesystemAdapter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(adapter, resolver)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return ts, pub, priv, did
}

func doRequest(t *testing.T, ts *httptest.Server, method, path string, body []byte, headers map[string]string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func authHeaders(t *testing.T, priv ed25519.PrivateKey, did, method, path string, body []byte) map[string]string {
	t.Helper()
	ts, sig := signRequest(t, priv, did, method, path, body)
	return map[string]string{
		"X-GT-DID":       did,
		"X-GT-Timestamp": ts,
		"X-GT-Signature": sig,
	}
}

func blobPath(did, hexHash string) string {
	return "/gt/v1/" + did + "/blobs/sha256/" + hexHash
}

func headPath(did, name string) string {
	return "/gt/v1/" + did + "/heads/" + name
}

func blobHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// --- Tests ---

func TestHealth(t *testing.T) {
	ts, _, _, _ := setupTest(t)
	resp := doRequest(t, ts, "GET", "/gt/v1/health", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPutGetBlob(t *testing.T) {
	ts, _, priv, did := setupTest(t)

	data := []byte("hello world")
	hash := blobHash(data)
	path := blobPath(did, hash)

	// PUT blob
	headers := authHeaders(t, priv, did, "PUT", path, data)
	resp := doRequest(t, ts, "PUT", path, data, headers)
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT expected 201, got %d: %s", resp.StatusCode, body)
	}

	// GET blob
	resp = doRequest(t, ts, "GET", path, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET expected 200, got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, data) {
		t.Fatalf("GET body mismatch: got %q, want %q", got, data)
	}

	// Check Cache-Control header
	cc := resp.Header.Get("Cache-Control")
	if cc == "" {
		t.Fatal("expected Cache-Control header on blob GET")
	}
}

func TestPutBlobHashMismatch(t *testing.T) {
	ts, _, priv, did := setupTest(t)

	data := []byte("hello world")
	wrongHash := blobHash([]byte("wrong data"))
	path := blobPath(did, wrongHash)

	headers := authHeaders(t, priv, did, "PUT", path, data)
	resp := doRequest(t, ts, "PUT", path, data, headers)
	if resp.StatusCode != 422 {
		t.Fatalf("expected 422, got %d", resp.StatusCode)
	}
}

func TestPutBlobAlreadyExists(t *testing.T) {
	ts, _, priv, did := setupTest(t)

	data := []byte("hello world")
	hash := blobHash(data)
	path := blobPath(did, hash)

	// First PUT
	headers := authHeaders(t, priv, did, "PUT", path, data)
	resp := doRequest(t, ts, "PUT", path, data, headers)
	if resp.StatusCode != 201 {
		t.Fatalf("first PUT expected 201, got %d", resp.StatusCode)
	}

	// Second PUT
	headers = authHeaders(t, priv, did, "PUT", path, data)
	resp = doRequest(t, ts, "PUT", path, data, headers)
	if resp.StatusCode != 409 {
		t.Fatalf("second PUT expected 409, got %d", resp.StatusCode)
	}
}

func TestPutBlobNoAuth(t *testing.T) {
	ts, _, _, did := setupTest(t)

	data := []byte("hello world")
	hash := blobHash(data)
	path := blobPath(did, hash)

	resp := doRequest(t, ts, "PUT", path, data, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestDeleteBlob(t *testing.T) {
	ts, _, priv, did := setupTest(t)

	data := []byte("to be deleted")
	hash := blobHash(data)
	path := blobPath(did, hash)

	// PUT
	headers := authHeaders(t, priv, did, "PUT", path, data)
	doRequest(t, ts, "PUT", path, data, headers)

	// DELETE
	headers = authHeaders(t, priv, did, "DELETE", path, nil)
	resp := doRequest(t, ts, "DELETE", path, nil, headers)
	if resp.StatusCode != 204 {
		t.Fatalf("DELETE expected 204, got %d", resp.StatusCode)
	}

	// GET should 404
	resp = doRequest(t, ts, "GET", path, nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("GET after DELETE expected 404, got %d", resp.StatusCode)
	}
}

func TestDeleteBlobNotOwner(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(nil)
	_, priv2, _ := ed25519.GenerateKey(nil)
	did1 := "did:web:example.com:u:alice"
	did2 := "did:web:example.com:u:bob"

	resolver := &mockResolver{
		keys: map[string][][]byte{
			did1: {[]byte(priv1.Public().(ed25519.PublicKey))},
			did2: {[]byte(priv2.Public().(ed25519.PublicKey))},
		},
	}

	adapter, _ := storage.NewFilesystemAdapter(t.TempDir())
	srv := NewServer(adapter, resolver)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Alice puts blob in her namespace
	data := []byte("alice's data")
	hash := blobHash(data)
	alicePath := blobPath(did1, hash)

	headers := authHeaders(t, priv1, did1, "PUT", alicePath, data)
	resp := doRequest(t, ts, "PUT", alicePath, data, headers)
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT expected 201, got %d: %s", resp.StatusCode, body)
	}

	// Bob tries to delete alice's blob (signs as bob, targets alice's path)
	headers = authHeaders(t, priv2, did2, "DELETE", alicePath, nil)
	resp = doRequest(t, ts, "DELETE", alicePath, nil, headers)
	if resp.StatusCode != 403 {
		t.Fatalf("DELETE by non-owner expected 403, got %d", resp.StatusCode)
	}
}

func TestGetHeadNotFound(t *testing.T) {
	ts, _, _, did := setupTest(t)

	path := headPath(did, "manifest")
	resp := doRequest(t, ts, "GET", path, nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestPutGetHead(t *testing.T) {
	ts, _, priv, did := setupTest(t)

	path := headPath(did, "manifest")
	body, _ := json.Marshal(HeadUpdateRequest{
		Expected: "",
		Head:     "sha256-abc123",
	})

	// PUT head (initial)
	headers := authHeaders(t, priv, did, "PUT", path, body)
	resp := doRequest(t, ts, "PUT", path, body, headers)
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT head expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	// GET head
	resp = doRequest(t, ts, "GET", path, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET head expected 200, got %d", resp.StatusCode)
	}

	var head Head
	json.NewDecoder(resp.Body).Decode(&head)
	if head.Head != "sha256-abc123" {
		t.Fatalf("expected head sha256-abc123, got %s", head.Head)
	}
}

func TestHeadCASSuccess(t *testing.T) {
	ts, _, priv, did := setupTest(t)

	path := headPath(did, "manifest")

	// Create initial head
	body, _ := json.Marshal(HeadUpdateRequest{Expected: "", Head: "sha256-aaa"})
	headers := authHeaders(t, priv, did, "PUT", path, body)
	doRequest(t, ts, "PUT", path, body, headers)

	// CAS update: aaa → bbb
	body, _ = json.Marshal(HeadUpdateRequest{Expected: "sha256-aaa", Head: "sha256-bbb"})
	headers = authHeaders(t, priv, did, "PUT", path, body)
	resp := doRequest(t, ts, "PUT", path, body, headers)
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("CAS update expected 200, got %d: %s", resp.StatusCode, respBody)
	}

	// Verify
	resp = doRequest(t, ts, "GET", path, nil, nil)
	var head Head
	json.NewDecoder(resp.Body).Decode(&head)
	if head.Head != "sha256-bbb" {
		t.Fatalf("expected sha256-bbb, got %s", head.Head)
	}
}

func TestHeadCASConflict(t *testing.T) {
	ts, _, priv, did := setupTest(t)

	path := headPath(did, "manifest")

	// Create initial head
	body, _ := json.Marshal(HeadUpdateRequest{Expected: "", Head: "sha256-aaa"})
	headers := authHeaders(t, priv, did, "PUT", path, body)
	doRequest(t, ts, "PUT", path, body, headers)

	// CAS with wrong expected
	body, _ = json.Marshal(HeadUpdateRequest{Expected: "sha256-wrong", Head: "sha256-bbb"})
	headers = authHeaders(t, priv, did, "PUT", path, body)
	resp := doRequest(t, ts, "PUT", path, body, headers)
	if resp.StatusCode != 409 {
		t.Fatalf("CAS conflict expected 409, got %d", resp.StatusCode)
	}
}

func TestHeadOwnerCheck(t *testing.T) {
	adapter, _ := storage.NewFilesystemAdapter(t.TempDir())
	_, priv2, _ := ed25519.GenerateKey(nil)
	did1 := "did:web:example.com:u:alice"
	did2 := "did:web:example.com:u:bob"

	resolver := &mockResolver{
		keys: map[string][][]byte{
			did2: {[]byte(priv2.Public().(ed25519.PublicKey))},
		},
	}
	srv := NewServer(adapter, resolver)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Bob tries to PUT head in alice's namespace
	path := headPath(did1, "manifest")
	body, _ := json.Marshal(HeadUpdateRequest{Expected: "", Head: "sha256-evil"})
	headers := authHeaders(t, priv2, did2, "PUT", path, body)
	resp := doRequest(t, ts, "PUT", path, body, headers)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestFullChain(t *testing.T) {
	ts, _, priv, did := setupTest(t)

	// 1. Store blob1
	blob1 := []byte(`{"type":"post","text":"hello"}`)
	hash1 := blobHash(blob1)
	path1 := blobPath(did, hash1)
	headers := authHeaders(t, priv, did, "PUT", path1, blob1)
	resp := doRequest(t, ts, "PUT", path1, blob1, headers)
	if resp.StatusCode != 201 {
		t.Fatalf("blob1 PUT expected 201, got %d", resp.StatusCode)
	}

	// 2. Create head pointing to blob1
	headP := headPath(did, "manifest")
	headBody, _ := json.Marshal(HeadUpdateRequest{Expected: "", Head: "sha256-" + hash1})
	headers = authHeaders(t, priv, did, "PUT", headP, headBody)
	resp = doRequest(t, ts, "PUT", headP, headBody, headers)
	if resp.StatusCode != 200 {
		t.Fatalf("head create expected 200, got %d", resp.StatusCode)
	}

	// 3. Store blob2
	blob2 := []byte(`{"type":"post","text":"world"}`)
	hash2 := blobHash(blob2)
	path2 := blobPath(did, hash2)
	headers = authHeaders(t, priv, did, "PUT", path2, blob2)
	resp = doRequest(t, ts, "PUT", path2, blob2, headers)
	if resp.StatusCode != 201 {
		t.Fatalf("blob2 PUT expected 201, got %d", resp.StatusCode)
	}

	// 4. CAS move head from blob1 to blob2
	headBody, _ = json.Marshal(HeadUpdateRequest{Expected: "sha256-" + hash1, Head: "sha256-" + hash2})
	headers = authHeaders(t, priv, did, "PUT", headP, headBody)
	resp = doRequest(t, ts, "PUT", headP, headBody, headers)
	if resp.StatusCode != 200 {
		t.Fatalf("head CAS expected 200, got %d", resp.StatusCode)
	}

	// 5. Verify head points to blob2
	resp = doRequest(t, ts, "GET", headP, nil, nil)
	var head Head
	json.NewDecoder(resp.Body).Decode(&head)
	if head.Head != "sha256-"+hash2 {
		t.Fatalf("expected head sha256-%s, got %s", hash2, head.Head)
	}

	// 6. Verify both blobs still readable
	resp = doRequest(t, ts, "GET", path1, nil, nil)
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, blob1) {
		t.Fatal("blob1 content mismatch")
	}

	resp = doRequest(t, ts, "GET", path2, nil, nil)
	got, _ = io.ReadAll(resp.Body)
	if !bytes.Equal(got, blob2) {
		t.Fatal("blob2 content mismatch")
	}
}

// --- ACL Tests ---

func metaPath(did, hexHash string) string {
	return "/gt/v1/" + did + "/blobs/sha256/" + hexHash + ":meta"
}

// putBlob is a helper that PUTs a blob and asserts 201.
func putBlob(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey, did string, data []byte) string {
	t.Helper()
	hash := blobHash(data)
	path := blobPath(did, hash)
	headers := authHeaders(t, priv, did, "PUT", path, data)
	resp := doRequest(t, ts, "PUT", path, data, headers)
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT blob expected 201, got %d: %s", resp.StatusCode, body)
	}
	return hash
}

// putMeta is a helper that PUTs blob meta.
func putMeta(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey, did, hash string, meta BlobMeta) int {
	t.Helper()
	path := metaPath(did, hash)
	body, _ := json.Marshal(meta)
	headers := authHeaders(t, priv, did, "PUT", path, body)
	resp := doRequest(t, ts, "PUT", path, body, headers)
	return resp.StatusCode
}

func setupTwoUsers(t *testing.T) (*httptest.Server, ed25519.PrivateKey, string, ed25519.PrivateKey, string) {
	t.Helper()
	_, priv1, _ := ed25519.GenerateKey(nil)
	_, priv2, _ := ed25519.GenerateKey(nil)
	did1 := "did:web:example.com:u:alice"
	did2 := "did:web:example.com:u:bob"

	resolver := &mockResolver{
		keys: map[string][][]byte{
			did1: {[]byte(priv1.Public().(ed25519.PublicKey))},
			did2: {[]byte(priv2.Public().(ed25519.PublicKey))},
		},
	}
	adapter, _ := storage.NewFilesystemAdapter(t.TempDir())
	srv := NewServer(adapter, resolver)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, priv1, did1, priv2, did2
}

func TestBlobNoMeta_PublicByDefault(t *testing.T) {
	ts, priv, did, _, _ := setupTwoUsers(t)
	data := []byte("public blob")
	hash := putBlob(t, ts, priv, did, data)

	// Anonymous GET should work (backward compat)
	resp := doRequest(t, ts, "GET", blobPath(did, hash), nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, data) {
		t.Fatal("body mismatch")
	}
}

func TestBlobACLOwnerOnly(t *testing.T) {
	ts, priv1, did1, _, _ := setupTwoUsers(t)
	data := []byte("private blob")
	hash := putBlob(t, ts, priv1, did1, data)

	// Set ACL to owner-only
	code := putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{}})
	if code != 200 {
		t.Fatalf("PUT meta expected 200, got %d", code)
	}

	// Anonymous GET → 404
	resp := doRequest(t, ts, "GET", blobPath(did1, hash), nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("anonymous GET expected 404, got %d", resp.StatusCode)
	}

	// Owner GET → 200
	path := blobPath(did1, hash)
	headers := authHeaders(t, priv1, did1, "GET", path, nil)
	resp = doRequest(t, ts, "GET", path, nil, headers)
	if resp.StatusCode != 200 {
		t.Fatalf("owner GET expected 200, got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, data) {
		t.Fatal("body mismatch")
	}
}

func TestBlobACLSpecificDID(t *testing.T) {
	ts, priv1, did1, priv2, did2 := setupTwoUsers(t)
	data := []byte("shared blob")
	hash := putBlob(t, ts, priv1, did1, data)

	// Set ACL to allow bob
	code := putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{did2}})
	if code != 200 {
		t.Fatalf("PUT meta expected 200, got %d", code)
	}

	// Anonymous GET → 404
	resp := doRequest(t, ts, "GET", blobPath(did1, hash), nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("anonymous GET expected 404, got %d", resp.StatusCode)
	}

	// Bob GET → 200
	path := blobPath(did1, hash)
	headers := authHeaders(t, priv2, did2, "GET", path, nil)
	resp = doRequest(t, ts, "GET", path, nil, headers)
	if resp.StatusCode != 200 {
		t.Fatalf("bob GET expected 200, got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, data) {
		t.Fatal("body mismatch")
	}
}

func TestBlobACLPublicExplicit(t *testing.T) {
	ts, priv1, did1, _, _ := setupTwoUsers(t)
	data := []byte("explicit public blob")
	hash := putBlob(t, ts, priv1, did1, data)

	// Set ACL to public
	code := putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{"*"}})
	if code != 200 {
		t.Fatalf("PUT meta expected 200, got %d", code)
	}

	// Anonymous GET → 200
	resp := doRequest(t, ts, "GET", blobPath(did1, hash), nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("anonymous GET expected 200, got %d", resp.StatusCode)
	}
}

func TestDeleteBlobAlsoDeletesMeta(t *testing.T) {
	ts, priv1, did1, _, _ := setupTwoUsers(t)
	data := []byte("blob with meta")
	hash := putBlob(t, ts, priv1, did1, data)

	// Set meta
	putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{}})

	// Delete blob
	path := blobPath(did1, hash)
	headers := authHeaders(t, priv1, did1, "DELETE", path, nil)
	resp := doRequest(t, ts, "DELETE", path, nil, headers)
	if resp.StatusCode != 204 {
		t.Fatalf("DELETE expected 204, got %d", resp.StatusCode)
	}

	// Meta GET should 404
	mpath := metaPath(did1, hash)
	headers = authHeaders(t, priv1, did1, "GET", mpath, nil)
	resp = doRequest(t, ts, "GET", mpath, nil, headers)
	if resp.StatusCode != 404 {
		t.Fatalf("meta GET after delete expected 404, got %d", resp.StatusCode)
	}
}

func TestBlobMetaRequiresOwner(t *testing.T) {
	ts, priv1, did1, priv2, did2 := setupTwoUsers(t)
	data := []byte("alice's blob")
	hash := putBlob(t, ts, priv1, did1, data)

	// Bob tries to PUT meta on alice's blob
	path := metaPath(did1, hash)
	body, _ := json.Marshal(BlobMeta{ACL: []string{}})
	headers := authHeaders(t, priv2, did2, "PUT", path, body)
	resp := doRequest(t, ts, "PUT", path, body, headers)
	if resp.StatusCode != 403 {
		t.Fatalf("non-owner PUT meta expected 403, got %d", resp.StatusCode)
	}
}

func TestBlobMetaPutRequiresBlob(t *testing.T) {
	ts, priv1, did1, _, _ := setupTwoUsers(t)

	// Try to PUT meta for non-existent blob
	fakeHash := blobHash([]byte("does not exist"))
	code := putMeta(t, ts, priv1, did1, fakeHash, BlobMeta{ACL: []string{}})
	if code != 404 {
		t.Fatalf("PUT meta for non-existent blob expected 404, got %d", code)
	}
}

func TestBlobMetaGetOwnerOnly(t *testing.T) {
	ts, priv1, did1, priv2, did2 := setupTwoUsers(t)
	data := []byte("blob for meta test")
	hash := putBlob(t, ts, priv1, did1, data)
	putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{did2}})

	// Owner can GET meta
	path := metaPath(did1, hash)
	headers := authHeaders(t, priv1, did1, "GET", path, nil)
	resp := doRequest(t, ts, "GET", path, nil, headers)
	if resp.StatusCode != 200 {
		t.Fatalf("owner GET meta expected 200, got %d", resp.StatusCode)
	}

	var meta BlobMeta
	json.NewDecoder(resp.Body).Decode(&meta)
	if len(meta.ACL) != 1 || meta.ACL[0] != did2 {
		t.Fatalf("unexpected ACL: %v", meta.ACL)
	}

	// Bob cannot GET meta (not owner)
	headers = authHeaders(t, priv2, did2, "GET", path, nil)
	resp = doRequest(t, ts, "GET", path, nil, headers)
	if resp.StatusCode != 403 {
		t.Fatalf("non-owner GET meta expected 403, got %d", resp.StatusCode)
	}
}

func TestBlobMetaUpdate(t *testing.T) {
	ts, priv1, did1, _, did2 := setupTwoUsers(t)
	data := []byte("blob to update meta")
	hash := putBlob(t, ts, priv1, did1, data)

	// Create meta with owner-only
	code := putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{}})
	if code != 200 {
		t.Fatalf("first PUT meta expected 200, got %d", code)
	}

	// Update meta to allow bob
	code = putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{did2}})
	if code != 200 {
		t.Fatalf("second PUT meta expected 200, got %d", code)
	}

	// Verify meta was updated
	path := metaPath(did1, hash)
	headers := authHeaders(t, priv1, did1, "GET", path, nil)
	resp := doRequest(t, ts, "GET", path, nil, headers)
	var meta BlobMeta
	json.NewDecoder(resp.Body).Decode(&meta)
	if len(meta.ACL) != 1 || meta.ACL[0] != did2 {
		t.Fatalf("expected ACL [%s], got %v", did2, meta.ACL)
	}
	if meta.UpdatedAt == "" {
		t.Fatal("expected updatedAt to be set on update")
	}
}
