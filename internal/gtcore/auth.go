package gtcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"log"

	"greything/internal/crypto"
	"greything/internal/did"
)

const maxTimestampAge = 5 * time.Minute

// DIDResolver resolves a DID to its Ed25519 public keys.
type DIDResolver interface {
	ResolveEd25519Keys(did string) ([][]byte, error)
}

// HTTPDIDResolver resolves DIDs via HTTP (did:web method).
type HTTPDIDResolver struct {
	BaseURL string // e.g. "https://did.greything.com"
}

// ResolveEd25519Keys fetches the DID document and returns all Ed25519 public keys.
func (r *HTTPDIDResolver) ResolveEd25519Keys(didStr string) ([][]byte, error) {
	// did:web:did.greything.com → https://did.greything.com/.well-known/did.json
	// did:web:did.greything.com:u:anton → https://did.greything.com/u/anton/did.json
	url, err := didWebToURL(r.BaseURL, didStr)
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching DID document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DID document fetch returned %d", resp.StatusCode)
	}

	var doc did.DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding DID document: %w", err)
	}

	var keys [][]byte
	for _, vm := range doc.VerificationMethod {
		if vm.Type != "Ed25519VerificationKey2020" {
			continue
		}
		raw, err := crypto.DecodeMultibase(vm.PublicKeyMultibase)
		if err != nil {
			continue
		}
		if len(raw) == 32 {
			keys = append(keys, raw)
		}
	}

	if len(keys) == 0 {
		return nil, errors.New("no Ed25519 keys found in DID document")
	}
	return keys, nil
}

// didWebToURL converts a did:web DID to a URL.
// For DIDs on the same domain as baseURL, uses baseURL (allows localhost resolution).
// For external DIDs, resolves directly via the domain in the DID.
func didWebToURL(baseURL, didStr string) (string, error) {
	if !strings.HasPrefix(didStr, "did:web:") {
		return "", fmt.Errorf("unsupported DID method: %s", didStr)
	}

	parts := strings.Split(didStr[8:], ":") // strip "did:web:"
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid did:web: %s", didStr)
	}

	domain := parts[0]

	// Check if DID is on the same domain as baseURL
	base := baseURL
	parsedBase, err := url.Parse(baseURL)
	if err == nil && parsedBase.Host == domain {
		// Local DID — use baseURL for resolution
		base = baseURL
	} else {
		// External DID — resolve via the DID's own domain
		base = "https://" + domain
	}

	if len(parts) == 1 {
		return base + "/.well-known/did.json", nil
	}

	path := strings.Join(parts[1:], "/")
	return base + "/" + path + "/did.json", nil
}

// Authenticate verifies the request signature and returns the authenticated DID and buffered body.
// Auth headers: X-GT-DID, X-GT-Timestamp, X-GT-Signature
// Signature payload: "{timestamp}|{method}|{path}|{bodyHash}"
func Authenticate(r *http.Request, resolver DIDResolver) (*AuthInfo, []byte, error) {
	didStr := r.Header.Get("X-GT-DID")
	timestamp := r.Header.Get("X-GT-Timestamp")
	signature := r.Header.Get("X-GT-Signature")

	if didStr == "" || timestamp == "" || signature == "" {
		return nil, nil, errors.New("missing auth headers")
	}

	// Verify timestamp freshness
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid timestamp: %w", err)
	}
	if math.Abs(time.Since(ts).Seconds()) > maxTimestampAge.Seconds() {
		return nil, nil, errors.New("timestamp too old")
	}

	// Read and buffer body
	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("reading body: %w", err)
		}
	}

	// Compute body hash
	h := sha256.Sum256(body)
	bodyHash := "sha256-" + hex.EncodeToString(h[:])

	// Build signature payload
	payload := fmt.Sprintf("%s|%s|%s|%s", timestamp, r.Method, r.URL.Path, bodyHash)
	log.Printf("[auth] DID=%s method=%s path=%s bodyLen=%d payload=%s", didStr, r.Method, r.URL.Path, len(body), payload)

	// Decode signature
	sigBytes, err := crypto.DecodeBase64URL(signature)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Resolve DID to public keys
	keys, err := resolver.ResolveEd25519Keys(didStr)
	if err != nil {
		log.Printf("[auth] DID resolution failed: %v", err)
		return nil, nil, fmt.Errorf("resolving DID: %w", err)
	}
	log.Printf("[auth] resolved %d keys for %s", len(keys), didStr)

	// Try each key
	for _, pub := range keys {
		if crypto.VerifyEd25519Bytes(pub, []byte(payload), sigBytes) {
			log.Printf("[auth] OK for %s", didStr)
			return &AuthInfo{DID: didStr}, body, nil
		}
	}

	log.Printf("[auth] signature verification failed for %s", didStr)
	return nil, nil, errors.New("signature verification failed")
}

// TryAuthenticate optionally authenticates a request.
// If no auth headers are present, returns (nil, nil).
// If headers are present but invalid, returns an error.
func TryAuthenticate(r *http.Request, resolver DIDResolver, body []byte) (*AuthInfo, error) {
	didStr := r.Header.Get("X-GT-DID")
	timestamp := r.Header.Get("X-GT-Timestamp")
	signature := r.Header.Get("X-GT-Signature")

	if didStr == "" && timestamp == "" && signature == "" {
		return nil, nil
	}

	if didStr == "" || timestamp == "" || signature == "" {
		return nil, errors.New("incomplete auth headers")
	}

	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}
	if math.Abs(time.Since(ts).Seconds()) > maxTimestampAge.Seconds() {
		return nil, errors.New("timestamp too old")
	}

	if body == nil {
		body = []byte{}
	}

	h := sha256.Sum256(body)
	bodyHash := "sha256-" + hex.EncodeToString(h[:])

	payload := fmt.Sprintf("%s|%s|%s|%s", timestamp, r.Method, r.URL.Path, bodyHash)

	sigBytes, err := crypto.DecodeBase64URL(signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	keys, err := resolver.ResolveEd25519Keys(didStr)
	if err != nil {
		return nil, fmt.Errorf("resolving DID: %w", err)
	}

	for _, pub := range keys {
		if crypto.VerifyEd25519Bytes(pub, []byte(payload), sigBytes) {
			return &AuthInfo{DID: didStr}, nil
		}
	}

	return nil, errors.New("signature verification failed")
}
