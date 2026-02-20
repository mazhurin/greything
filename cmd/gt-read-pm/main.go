package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
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

type DIDDocument struct {
	ID                 string `json:"id"`
	VerificationMethod []struct {
		ID                 string `json:"id"`
		Type               string `json:"type"`
		Controller         string `json:"controller"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	} `json:"verificationMethod"`
}

type InboxCiphertextV1 struct {
	Type          string    `json:"type"`
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"createdAt"`
	EpkB64        string    `json:"epkB64"`
	NonceB64      string    `json:"nonceB64"`
	CiphertextB64 string    `json:"ciphertextB64"`
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

func main() {
	var bobXKeyPath string
	var blobURL string
	var didRegistry string

	flag.StringVar(&bobXKeyPath, "bob-xkey", "", "Bob X25519 private key JSON file. Required.")
	flag.StringVar(&blobURL, "blob", "", "URL of ciphertext blob (from gt-send-pm). Required.")
	flag.StringVar(&didRegistry, "did-registry", "http://localhost:8080", "DID registry base URL (for signature verification).")
	flag.Parse()

	if bobXKeyPath == "" || blobURL == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/gt-read-pm --bob-xkey .greything/keys/bob-x25519.json --blob http://.../objects/....json [--did-registry http://localhost:8080]")
		os.Exit(2)
	}

	// Load Bob X25519 private key
	bobKF, err := readKeyFile(bobXKeyPath)
	if err != nil {
		panic(err)
	}

    kty := strings.ToLower(strings.TrimSpace(bobKF.KTY))
    if kty != "" && kty != "x25519" {
        panic("bob-xkey must be X25519 keyfile (kty=X25519)")
    }

	bobPrivBytes, err := base64.RawURLEncoding.DecodeString(bobKF.PrivateKeyB64URL)
	if err != nil {
		panic(err)
	}
	if len(bobPrivBytes) != 32 {
		panic(fmt.Sprintf("expected bob x25519 private key 32 bytes, got %d", len(bobPrivBytes)))
	}

	curve := ecdh.X25519()
	bobPriv, err := curve.NewPrivateKey(bobPrivBytes)
	if err != nil {
		panic(err)
	}

	// Fetch ciphertext blob
	ct, raw, err := fetchCiphertext(blobURL)
	if err != nil {
		panic(err)
	}
	_ = raw

	epk, err := base64.RawURLEncoding.DecodeString(ct.EpkB64)
	if err != nil {
		panic(err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(ct.NonceB64)
	if err != nil {
		panic(err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(ct.CiphertextB64)
	if err != nil {
		panic(err)
	}

	if len(epk) != 32 {
		panic("epk must be 32 bytes")
	}

	epkPub, err := curve.NewPublicKey(epk)
	if err != nil {
		panic(err)
	}

	shared, err := bobPriv.ECDH(epkPub)
	if err != nil {
		panic(err)
	}

	// Derive AEAD key
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
	if len(nonce) != aead.NonceSize() {
		panic(fmt.Sprintf("bad nonce size: got %d want %d", len(nonce), aead.NonceSize()))
	}

	innerBytes, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(fmt.Errorf("decrypt failed: %w", err))
	}

	var inner SignedInnerMessageV1
	if err := json.Unmarshal(innerBytes, &inner); err != nil {
		panic(err)
	}

	// Verify signature
	ok, verr := verifyInnerSignature(&inner, strings.TrimRight(didRegistry, "/"))
	if verr != nil {
		panic(verr)
	}

	fmt.Println("DECRYPT OK")
	fmt.Println("PM ID:", inner.ID)
	fmt.Println("From:", inner.From)
	fmt.Println("To:", inner.To)
	fmt.Println("CreatedAt:", inner.CreatedAt.Format(time.RFC3339Nano))
	fmt.Println("Text:", inner.Text)
	fmt.Println("Signature KID:", inner.Signature.KID)
	fmt.Println("Signature valid:", ok)
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

func fetchCiphertext(url string) (*InboxCiphertextV1, []byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("GET %s: %s: %s", url, resp.Status, string(b))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	var ct InboxCiphertextV1
	if err := json.Unmarshal(b, &ct); err != nil {
		return nil, nil, err
	}
	return &ct, b, nil
}

func verifyInnerSignature(m *SignedInnerMessageV1, didRegistry string) (bool, error) {
	if m.Signature.Alg != "Ed25519" {
		return false, fmt.Errorf("unsupported signature alg: %s", m.Signature.Alg)
	}
	// KID is like: did:web:greything.com:users:alice#device-2026-01-21
	kid := m.Signature.KID
	hash := strings.Index(kid, "#")
	if hash < 0 {
		return false, fmt.Errorf("bad kid: %s", kid)
	}
	authorDID := kid[:hash]
	keyFragment := kid[hash+1:]

	authorUser := didWebUsername(authorDID)
	if authorUser == "" {
		return false, fmt.Errorf("unsupported author DID: %s", authorDID)
	}

	authorDidURL := didRegistry + "/users/" + authorUser + "/did.json"
	doc, err := fetchDID(authorDidURL)
	if err != nil {
		return false, err
	}

	// Find matching verification method in DID doc
	wantVMID := authorDID + "#" + keyFragment
	var pubMB string
	for _, vm := range doc.VerificationMethod {
		if vm.ID == wantVMID && vm.Type == "Ed25519VerificationKey2020" {
			pubMB = vm.PublicKeyMultibase
			break
		}
	}
	if pubMB == "" {
		return false, fmt.Errorf("no matching Ed25519 verificationMethod in DID doc for %s", wantVMID)
	}
	pubBytes, err := crypto.Base58Decode(strings.TrimPrefix(pubMB, "z"))
	if err != nil {
		return false, err
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("bad ed25519 pub size: %d", len(pubBytes))
	}
	pub := ed25519.PublicKey(pubBytes)

	sig, err := base64.RawURLEncoding.DecodeString(m.Signature.Sig)
	if err != nil {
		return false, err
	}

	canon := canonicalInner(*m)
	return ed25519.Verify(pub, []byte(canon), sig), nil
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

func didWebUsername(didStr string) string {
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
	// Must match gt-send-pm canonicalization
	var b bytes.Buffer
	b.WriteString("type=" + m.Type + "\n")
	b.WriteString("id=" + m.ID + "\n")
	b.WriteString("from=" + m.From + "\n")
	b.WriteString("to=" + m.To + "\n")
	b.WriteString("createdAt=" + m.CreatedAt.Format(time.RFC3339Nano) + "\n")
	b.WriteString("text=" + m.Text + "\n")
	return b.String()
}
