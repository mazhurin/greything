package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"greything/internal/crypto"
)

type KeyFile struct {
	KTY                string `json:"kty"` // "Ed25519" or "X25519"
	KID                string `json:"kid"`
	CreatedAt          string `json:"createdAt"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	PrivateKeyB64URL   string `json:"privateKeyB64Url"`
}

// Minimal DID doc for our needs
type DIDDocument struct {
	ID                 string `json:"id"`
	VerificationMethod []struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	} `json:"verificationMethod"`
	KeyAgreement []string `json:"keyAgreement"`
}

type SignedInnerMessageV1 struct {
	Type      string    `json:"type"`
	ID        string    `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	CreatedAt time.Time `json:"createdAt"`
	Text      string    `json:"text"`

	Signature struct {
		KID string `json:"kid"`
		Alg string `json:"alg"`
		Sig string `json:"sig"` // base64url
	} `json:"signature"`
}

type InboxCiphertextV1 struct {
	Type        string    `json:"type"`
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"createdAt"`
	EpkB64      string    `json:"epkB64"`      // ephemeral X25519 pubkey (32 bytes)
	NonceB64    string    `json:"nonceB64"`    // 12 bytes
	CiphertextB64 string  `json:"ciphertextB64"`
}

func main() {
	var fromKeyPath string
	var fromDID string
	var toDID string
	var text string
	var didRegistry string
	var podBase string

	flag.StringVar(&fromKeyPath, "from-key", "", "Alice Ed25519 key JSON file (private). Required.")
	flag.StringVar(&fromDID, "from", "", "Alice DID. Required.")
	flag.StringVar(&toDID, "to", "", "Bob DID. Required.")
	flag.StringVar(&text, "text", "", "Message text. Required.")
	flag.StringVar(&didRegistry, "did-registry", "http://localhost:8080", "DID registry base URL.")
	flag.StringVar(&podBase, "pod", "", "Bob pod base URL override, e.g. http://localhost:8081/u/bob. If empty, derived from --to did:web...:users:bob")
	flag.Parse()

	if fromKeyPath == "" || fromDID == "" || toDID == "" || text == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/gt-send-pm --from-key <alice-ed25519.json> --from <aliceDID> --to <bobDID> --text \"hi\" [--did-registry http://localhost:8080] [--pod http://localhost:8081/u/bob]")
		os.Exit(2)
	}

	// Load Alice key
	aliceKF, err := readKeyFile(fromKeyPath)
	if err != nil {
		panic(err)
	}
	if strings.ToLower(aliceKF.KTY) != "ed25519" {
		panic("from-key must be Ed25519 keyfile (kty=Ed25519)")
	}
	alicePrivRaw, err := base64.RawURLEncoding.DecodeString(aliceKF.PrivateKeyB64URL)
	if err != nil {
		panic(err)
	}
	if len(alicePrivRaw) != ed25519.PrivateKeySize {
		panic(fmt.Sprintf("expected ed25519 private key 64 bytes, got %d", len(alicePrivRaw)))
	}
	alicePriv := ed25519.PrivateKey(alicePrivRaw)

	// Resolve Bob username from DID
	bobUser := didWebUsername(toDID)
	if bobUser == "" {
		panic("unsupported --to DID (expected did:web:...:users:<username>)")
	}

	// Fetch Bob DID doc
	didRegistry = strings.TrimRight(didRegistry, "/")
	bobDidURL := didRegistry + "/users/" + bobUser + "/did.json"
	bobDoc, err := fetchDID(bobDidURL)
	if err != nil {
		panic(err)
	}

	// Pick Bob X25519 pubkey from DID doc
	bobXPubMB, err := pickX25519Pub(bobDoc)
	if err != nil {
		panic(err)
	}
	bobXPubBytes, err := crypto.Base58Decode(strings.TrimPrefix(bobXPubMB, "z"))
	if err != nil {
		panic(err)
	}
	if len(bobXPubBytes) != 32 {
		panic("bob X25519 pubkey must be 32 bytes after base58 decode")
	}

	// Build + sign inner message
	now := time.Now().UTC()
	msgID := "urn:gt:pm:" + now.Format("20060102T150405.000000000Z")

	inner := SignedInnerMessageV1{
		Type:      "SignedInnerMessageV1",
		ID:        msgID,
		From:      fromDID,
		To:        toDID,
		CreatedAt: now,
		Text:      text,
	}
	canon := canonicalInner(inner)
	sig := ed25519.Sign(alicePriv, []byte(canon))
	inner.Signature.KID = fromDID + "#" + aliceKF.KID
	inner.Signature.Alg = "Ed25519"
	inner.Signature.Sig = base64.RawURLEncoding.EncodeToString(sig)

	innerBytes, _ := json.Marshal(inner)

	// Encrypt for Bob: X25519(ECDH) -> HKDF-SHA256 -> ChaCha20-Poly1305
	curve := ecdh.X25519()
	ephemPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ephemPub := ephemPriv.PublicKey().Bytes()

	bobPub, err := curve.NewPublicKey(bobXPubBytes)
	if err != nil {
		panic(err)
	}
	shared, err := ephemPriv.ECDH(bobPub)
	if err != nil {
		panic(err)
	}

	info := []byte("greything.pm.v1")
	kdf := hkdf.New(sha256.New, shared, nil, info)
	aeadKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, aeadKey); err != nil {
		panic(err)
	}

	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ciphertext := aead.Seal(nil, nonce, innerBytes, nil)

	out := InboxCiphertextV1{
		Type:          "InboxCiphertextV1",
		ID:            msgID,
		CreatedAt:     now,
		EpkB64:        base64.RawURLEncoding.EncodeToString(ephemPub),
		NonceB64:      base64.RawURLEncoding.EncodeToString(nonce),
		CiphertextB64: base64.RawURLEncoding.EncodeToString(ciphertext),
	}

	// Where to PUT (pod-mock): use /objects for now
	if podBase == "" {
		podBase = "http://localhost:8081/u/" + bobUser
	}
	podBase = strings.TrimRight(podBase, "/")
	putURL := podBase + "/objects/" + fileSafe(msgID)

	if err := httpPutJSON(putURL, out); err != nil {
		panic(err)
	}

	fmt.Println("OK: wrote PM ciphertext to:", putURL)
	fmt.Println("PM ID:", msgID)
	fmt.Println("Alice KID:", inner.Signature.KID)
}

func readKeyFile(path string) (*KeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k KeyFile
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

func fetchDID(url string) (*DIDDocument, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET %s: %s: %s", url, resp.Status, string(b))
	}
	var doc DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func pickX25519Pub(doc *DIDDocument) (string, error) {
	// Prefer first keyAgreement reference
	if len(doc.KeyAgreement) > 0 {
		want := doc.KeyAgreement[0]
		for _, vm := range doc.VerificationMethod {
			if vm.ID == want && vm.Type == "X25519KeyAgreementKey2020" {
				return vm.PublicKeyMultibase, nil
			}
		}
	}
	// Fallback: first X25519 method
	for _, vm := range doc.VerificationMethod {
		if vm.Type == "X25519KeyAgreementKey2020" {
			return vm.PublicKeyMultibase, nil
		}
	}
	return "", fmt.Errorf("no X25519KeyAgreementKey2020 in did doc")
}

func didWebUsername(didStr string) string {
	// did:web:greything.com:users:bob
	parts := strings.Split(didStr, ":")
	if len(parts) < 5 {
		return ""
	}
	if parts[0] != "did" || parts[1] != "web" {
		return ""
	}
	return parts[len(parts)-1]
}

func canonicalInner(m SignedInnerMessageV1) string {
	// Minimal deterministic string (v1). Later we can reuse your shared canonicalization module.
	var b bytes.Buffer
	b.WriteString("type=" + m.Type + "\n")
	b.WriteString("id=" + m.ID + "\n")
	b.WriteString("from=" + m.From + "\n")
	b.WriteString("to=" + m.To + "\n")
	b.WriteString("createdAt=" + m.CreatedAt.Format(time.RFC3339Nano) + "\n")
	b.WriteString("text=" + m.Text + "\n")
	return b.String()
}

func fileSafe(id string) string {
	// pod-mock path-friendly name
	s := strings.ReplaceAll(id, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s + ".json"
}

func httpPutJSON(url string, v any) error {
	b, _ := json.Marshal(v)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PUT %s: %s: %s", url, resp.Status, string(body))
	}
	return nil
}
