package gtcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"greything/internal/crypto"
)

// Grant represents a signed capability grant (gt.grant.v1).
type Grant struct {
	Type      string        `json:"type"`
	Issuer    string        `json:"issuer"`
	Subject   string        `json:"subject"`
	Resource  GrantResource `json:"resource"`
	Perm      []string      `json:"perm"`
	NotBefore string        `json:"notBefore"`
	ExpiresAt string        `json:"expiresAt"`
	Nonce     string        `json:"nonce"`
	Sig       *GrantSig     `json:"sig,omitempty"`
}

// GrantResource identifies what the grant applies to.
type GrantResource struct {
	Kind string `json:"kind"`
	Hash string `json:"hash"`
}

// GrantSig holds the signature over the grant.
type GrantSig struct {
	Alg   string `json:"alg"`
	KID   string `json:"kid"`
	Value string `json:"value"`
}

// CanonicalGrantBytesForSigning returns the canonical JSON of the grant
// with the sig field removed, suitable for signing/verification.
func CanonicalGrantBytesForSigning(g Grant) ([]byte, error) {
	// Marshal to map, remove sig, canonicalize
	data, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("marshaling grant: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshaling grant to map: %w", err)
	}
	delete(m, "sig")
	return crypto.CanonicalJSON(m)
}

// ComputeGrantHash returns "sha256-<hex>" of the canonical JSON of the
// full grant (including sig).
func ComputeGrantHash(g Grant) (string, error) {
	data, err := json.Marshal(g)
	if err != nil {
		return "", fmt.Errorf("marshaling grant: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("unmarshaling grant to map: %w", err)
	}
	canonical, err := crypto.CanonicalJSON(m)
	if err != nil {
		return "", fmt.Errorf("canonicalizing grant: %w", err)
	}
	h := sha256.Sum256(canonical)
	return "sha256-" + hex.EncodeToString(h[:]), nil
}

// VerifyGrant checks that the grant has correct type, required fields, and
// a valid signature from the issuer.
func VerifyGrant(g Grant, resolver DIDResolver) error {
	if g.Type != "gt.grant.v1" {
		return errors.New("invalid grant type")
	}
	if g.Issuer == "" {
		return errors.New("missing issuer")
	}
	if g.Subject == "" {
		return errors.New("missing subject")
	}
	if g.Resource.Kind == "" || g.Resource.Hash == "" {
		return errors.New("missing resource")
	}
	if len(g.Perm) == 0 {
		return errors.New("missing permissions")
	}
	if g.Sig == nil {
		return errors.New("missing signature")
	}
	if g.Sig.Alg != "Ed25519" {
		return fmt.Errorf("unsupported signature algorithm: %s", g.Sig.Alg)
	}

	// Get canonical bytes for verification
	canonical, err := CanonicalGrantBytesForSigning(g)
	if err != nil {
		return fmt.Errorf("canonicalizing grant: %w", err)
	}

	// Decode signature
	sigBytes, err := crypto.DecodeBase64URL(g.Sig.Value)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	// Resolve issuer's keys
	keys, err := resolver.ResolveEd25519Keys(g.Issuer)
	if err != nil {
		return fmt.Errorf("resolving issuer DID: %w", err)
	}

	// Try each key
	for _, pub := range keys {
		if crypto.VerifyEd25519Bytes(pub, canonical, sigBytes) {
			return nil
		}
	}

	return errors.New("grant signature verification failed")
}

// ValidateGrantForBlobRead checks that a verified grant authorizes the
// given reader to read the given blob from the given owner.
func ValidateGrantForBlobRead(g Grant, readerDID, blobOwnerDID, blobHash string, now time.Time) error {
	// Grant issuer must be the blob owner
	if g.Issuer != blobOwnerDID {
		return errors.New("grant issuer is not the blob owner")
	}

	// Grant subject must be the reader
	if g.Subject != readerDID {
		return errors.New("grant subject does not match reader")
	}

	// Resource must match
	if g.Resource.Kind != "blob" {
		return fmt.Errorf("grant resource kind is %q, expected \"blob\"", g.Resource.Kind)
	}
	if g.Resource.Hash != blobHash {
		return errors.New("grant resource hash does not match blob")
	}

	// Must have "read" permission
	hasRead := false
	for _, p := range g.Perm {
		if p == "read" {
			hasRead = true
			break
		}
	}
	if !hasRead {
		return errors.New("grant does not include read permission")
	}

	// Check time bounds
	if g.NotBefore != "" {
		nb, err := time.Parse(time.RFC3339, g.NotBefore)
		if err != nil {
			return fmt.Errorf("invalid notBefore: %w", err)
		}
		if now.Before(nb) {
			return errors.New("grant is not yet valid (notBefore)")
		}
	}
	if g.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, g.ExpiresAt)
		if err != nil {
			return fmt.Errorf("invalid expiresAt: %w", err)
		}
		if now.After(exp) {
			return errors.New("grant has expired")
		}
	}

	return nil
}

// grantKey returns the storage key for a grant.
func grantKey(did, grantHash string) string {
	// Strip "sha256-" prefix for filesystem path
	hash := grantHash
	if len(hash) > 7 && hash[:7] == "sha256-" {
		hash = hash[7:]
	}
	return did + "/grants/" + hash
}
