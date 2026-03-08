package gtcore

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"greything/internal/crypto"
	"greything/internal/storage"
)

// --- Grant unit tests ---

func makeTestGrant(issuer, subject, blobHash string) Grant {
	return Grant{
		Type:    "gt.grant.v1",
		Issuer:  issuer,
		Subject: subject,
		Resource: GrantResource{
			Kind: "blob",
			Hash: blobHash,
		},
		Perm:      []string{"read"},
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Nonce:     "testnonce123",
	}
}

func signGrant(t *testing.T, g *Grant, priv ed25519.PrivateKey, kid string) {
	t.Helper()
	canonical, err := CanonicalGrantBytesForSigning(*g)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canonical)
	g.Sig = &GrantSig{
		Alg:   "Ed25519",
		KID:   kid,
		Value: crypto.EncodeBase64URL(sig),
	}
}

func TestCanonicalGrantBytesForSigning(t *testing.T) {
	g := makeTestGrant("did:web:example.com:u:alice", "did:web:example.com:u:bob", "sha256-aaaa")
	g.Sig = &GrantSig{Alg: "Ed25519", KID: "key-1", Value: "dummysig"}

	bytes1, err := CanonicalGrantBytesForSigning(g)
	if err != nil {
		t.Fatal(err)
	}

	// Changing the sig should not change canonical bytes for signing
	g.Sig.Value = "differentsig"
	bytes2, err := CanonicalGrantBytesForSigning(g)
	if err != nil {
		t.Fatal(err)
	}

	if string(bytes1) != string(bytes2) {
		t.Fatal("canonical bytes should be identical regardless of sig value")
	}
}

func TestComputeGrantHash(t *testing.T) {
	g := makeTestGrant("did:web:example.com:u:alice", "did:web:example.com:u:bob", "sha256-aaaa")
	g.Sig = &GrantSig{Alg: "Ed25519", KID: "key-1", Value: "sig1"}

	hash1, err := ComputeGrantHash(g)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash1) < 10 || hash1[:7] != "sha256-" {
		t.Fatalf("unexpected hash format: %s", hash1)
	}

	// Different sig → different hash
	g.Sig.Value = "sig2"
	hash2, err := ComputeGrantHash(g)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 == hash2 {
		t.Fatal("different sigs should produce different hashes")
	}
}

func TestVerifyGrantRoundtrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	did := "did:web:example.com:u:alice"

	resolver := &mockResolver{
		keys: map[string][][]byte{
			did: {[]byte(pub)},
		},
	}

	g := makeTestGrant(did, "did:web:example.com:u:bob", "sha256-aaaa")
	signGrant(t, &g, priv, did+"#key-1")

	if err := VerifyGrant(g, resolver); err != nil {
		t.Fatalf("VerifyGrant failed: %v", err)
	}
}

func TestVerifyGrantBadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	did := "did:web:example.com:u:alice"

	resolver := &mockResolver{
		keys: map[string][][]byte{
			did: {[]byte(pub)},
		},
	}

	g := makeTestGrant(did, "did:web:example.com:u:bob", "sha256-aaaa")
	signGrant(t, &g, wrongPriv, did+"#key-1")

	err := VerifyGrant(g, resolver)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestValidateGrantForBlobRead(t *testing.T) {
	alice := "did:web:example.com:u:alice"
	bob := "did:web:example.com:u:bob"
	charlie := "did:web:example.com:u:charlie"
	blobHash := "sha256-aaaa"
	now := time.Now().UTC()

	g := makeTestGrant(alice, bob, blobHash)

	// Valid
	if err := ValidateGrantForBlobRead(g, bob, alice, blobHash, now); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	// Wrong subject
	if err := ValidateGrantForBlobRead(g, charlie, alice, blobHash, now); err == nil {
		t.Fatal("expected error for wrong subject")
	}

	// Wrong issuer (not blob owner)
	if err := ValidateGrantForBlobRead(g, bob, charlie, blobHash, now); err == nil {
		t.Fatal("expected error for wrong issuer")
	}

	// Wrong blob hash
	if err := ValidateGrantForBlobRead(g, bob, alice, "sha256-bbbb", now); err == nil {
		t.Fatal("expected error for wrong blob hash")
	}
}

func TestValidateGrantExpired(t *testing.T) {
	alice := "did:web:example.com:u:alice"
	bob := "did:web:example.com:u:bob"
	blobHash := "sha256-aaaa"

	g := makeTestGrant(alice, bob, blobHash)
	g.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)

	now := time.Now().UTC()
	if err := ValidateGrantForBlobRead(g, bob, alice, blobHash, now); err == nil {
		t.Fatal("expected error for expired grant")
	}
}

func TestValidateGrantNotYetValid(t *testing.T) {
	alice := "did:web:example.com:u:alice"
	bob := "did:web:example.com:u:bob"
	blobHash := "sha256-aaaa"

	g := makeTestGrant(alice, bob, blobHash)
	g.NotBefore = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	now := time.Now().UTC()
	if err := ValidateGrantForBlobRead(g, bob, alice, blobHash, now); err == nil {
		t.Fatal("expected error for not-yet-valid grant")
	}
}

// --- Grant HTTP endpoint tests ---

func grantPath(did string) string {
	return "/gt/v1/" + did + "/grants"
}

func grantItemPath(did, hash string) string {
	// Strip sha256- prefix for URL
	h := hash
	if len(h) > 7 && h[:7] == "sha256-" {
		h = h[7:]
	}
	return "/gt/v1/" + did + "/grants/" + h
}

func TestPostAndGetGrant(t *testing.T) {
	ts, priv1, did1, _, did2 := setupTwoUsers(t)

	// Alice creates a blob
	data := []byte("secret data")
	hash := putBlob(t, ts, priv1, did1, data)
	blobHashFull := "sha256-" + hash

	// Alice creates a grant for Bob
	g := makeTestGrant(did1, did2, blobHashFull)
	signGrant(t, &g, priv1, did1+"#key-1")

	grantBody, _ := json.Marshal(g)
	path := grantPath(did1)
	headers := authHeaders(t, priv1, did1, "POST", path, grantBody)
	resp := doRequest(t, ts, "POST", path, grantBody, headers)
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST grant expected 201, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	grantHash := result["grantHash"]
	if grantHash == "" {
		t.Fatal("expected grantHash in response")
	}

	// GET the grant back (public, no auth)
	getPath := grantItemPath(did1, grantHash)
	resp = doRequest(t, ts, "GET", getPath, nil, nil)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET grant expected 200, got %d: %s", resp.StatusCode, body)
	}

	var fetched Grant
	json.NewDecoder(resp.Body).Decode(&fetched)
	if fetched.Type != "gt.grant.v1" {
		t.Fatalf("unexpected type: %s", fetched.Type)
	}
	if fetched.Subject != did2 {
		t.Fatalf("unexpected subject: %s", fetched.Subject)
	}
}

func TestBlobAccessWithGrant(t *testing.T) {
	ts, priv1, did1, priv2, did2 := setupTwoUsers(t)

	// Alice creates a private blob
	data := []byte("private attachment data")
	hash := putBlob(t, ts, priv1, did1, data)
	blobHashFull := "sha256-" + hash

	// Set ACL to private
	code := putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{}})
	if code != 200 {
		t.Fatalf("PUT meta expected 200, got %d", code)
	}

	// Bob can't read without grant
	path := blobPath(did1, hash)
	headers := authHeaders(t, priv2, did2, "GET", path, nil)
	resp := doRequest(t, ts, "GET", path, nil, headers)
	if resp.StatusCode != 404 {
		t.Fatalf("GET without grant expected 404, got %d", resp.StatusCode)
	}

	// Alice creates and uploads grant for Bob
	g := makeTestGrant(did1, did2, blobHashFull)
	signGrant(t, &g, priv1, did1+"#key-1")

	grantBody, _ := json.Marshal(g)
	grantPostPath := grantPath(did1)
	grantHeaders := authHeaders(t, priv1, did1, "POST", grantPostPath, grantBody)
	resp = doRequest(t, ts, "POST", grantPostPath, grantBody, grantHeaders)
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST grant expected 201, got %d: %s", resp.StatusCode, body)
	}
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	grantHash := result["grantHash"]

	// Bob reads with grant header
	headers = authHeaders(t, priv2, did2, "GET", path, nil)
	headers["X-GT-Grant"] = grantHash
	resp = doRequest(t, ts, "GET", path, nil, headers)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET with grant expected 200, got %d: %s", resp.StatusCode, body)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(data) {
		t.Fatal("body mismatch")
	}
}

func TestBlobAccessGrantExpired(t *testing.T) {
	ts, priv1, did1, priv2, did2 := setupTwoUsers(t)

	data := []byte("private blob")
	hash := putBlob(t, ts, priv1, did1, data)
	blobHashFull := "sha256-" + hash
	putMeta(t, ts, priv1, did1, hash, BlobMeta{ACL: []string{}})

	// Expired grant
	g := makeTestGrant(did1, did2, blobHashFull)
	g.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	signGrant(t, &g, priv1, did1+"#key-1")

	grantBody, _ := json.Marshal(g)
	grantPostPath := grantPath(did1)
	grantHeaders := authHeaders(t, priv1, did1, "POST", grantPostPath, grantBody)
	resp := doRequest(t, ts, "POST", grantPostPath, grantBody, grantHeaders)
	if resp.StatusCode != 201 {
		t.Fatalf("POST grant expected 201, got %d", resp.StatusCode)
	}
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	path := blobPath(did1, hash)
	headers := authHeaders(t, priv2, did2, "GET", path, nil)
	headers["X-GT-Grant"] = result["grantHash"]
	resp = doRequest(t, ts, "GET", path, nil, headers)
	if resp.StatusCode != 404 {
		t.Fatalf("GET with expired grant expected 404, got %d", resp.StatusCode)
	}
}

func TestBlobAccessGrantWrongSubject(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(nil)
	_, priv2, _ := ed25519.GenerateKey(nil)
	_, priv3, _ := ed25519.GenerateKey(nil)
	did1 := "did:web:example.com:u:alice"
	did2 := "did:web:example.com:u:bob"
	did3 := "did:web:example.com:u:charlie"

	resolver := &mockResolver{
		keys: map[string][][]byte{
			did1: {[]byte(priv1.Public().(ed25519.PublicKey))},
			did2: {[]byte(priv2.Public().(ed25519.PublicKey))},
			did3: {[]byte(priv3.Public().(ed25519.PublicKey))},
		},
	}
	adapter, _ := storage.NewFilesystemAdapter(t.TempDir())
	srv := NewServer(adapter, resolver)
	tsSrv := httptest.NewServer(srv.Handler())
	defer tsSrv.Close()

	data := []byte("alice private data")
	hash := putBlob(t, tsSrv, priv1, did1, data)
	blobHashFull := "sha256-" + hash
	putMeta(t, tsSrv, priv1, did1, hash, BlobMeta{ACL: []string{}})

	// Grant for Bob, not Charlie
	g := makeTestGrant(did1, did2, blobHashFull)
	signGrant(t, &g, priv1, did1+"#key-1")

	grantBody, _ := json.Marshal(g)
	grantPostPath := grantPath(did1)
	grantHeaders := authHeaders(t, priv1, did1, "POST", grantPostPath, grantBody)
	resp := doRequest(t, tsSrv, "POST", grantPostPath, grantBody, grantHeaders)
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	// Charlie tries to use Bob's grant
	path := blobPath(did1, hash)
	headers := authHeaders(t, priv3, did3, "GET", path, nil)
	headers["X-GT-Grant"] = result["grantHash"]
	resp = doRequest(t, tsSrv, "GET", path, nil, headers)
	if resp.StatusCode != 404 {
		t.Fatalf("GET with wrong subject grant expected 404, got %d", resp.StatusCode)
	}
}

func TestGrantPostRequiresAuth(t *testing.T) {
	ts, priv1, did1, _, did2 := setupTwoUsers(t)

	g := makeTestGrant(did1, did2, "sha256-aaaa")
	signGrant(t, &g, priv1, did1+"#key-1")
	grantBody, _ := json.Marshal(g)

	// POST without auth
	resp := doRequest(t, ts, "POST", grantPath(did1), grantBody, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestGrantPostIssuerMustMatchRoute(t *testing.T) {
	ts, _, _, priv2, did2 := setupTwoUsers(t)
	did1 := "did:web:example.com:u:alice"

	// Bob tries to post a grant in Alice's namespace
	g := makeTestGrant(did1, did2, "sha256-aaaa")
	signGrant(t, &g, priv2, did2+"#key-1") // signed by Bob, but issuer says Alice
	grantBody, _ := json.Marshal(g)

	path := grantPath(did1)
	headers := authHeaders(t, priv2, did2, "POST", path, grantBody)
	resp := doRequest(t, ts, "POST", path, grantBody, headers)
	if resp.StatusCode != 403 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, body)
	}
}

func TestGrantNotFound(t *testing.T) {
	ts, _, _, _, _ := setupTwoUsers(t)
	did := "did:web:example.com:u:alice"

	resp := doRequest(t, ts, "GET", fmt.Sprintf("/gt/v1/%s/grants/%s", did, "0000000000000000000000000000000000000000000000000000000000000000"), nil, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}
