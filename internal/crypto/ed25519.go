package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

// base64url without padding
func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Decode multibase base58btc public key: "z...."
func DecodeMultibaseEd25519Pub(multibase string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(multibase, "z") {
		return nil, errors.New("only base58btc multibase (prefix z) supported")
	}
	raw, err := base58Decode(multibase[1:]) // <— теперь берём из base58.go
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("unexpected ed25519 pubkey size")
	}
	return ed25519.PublicKey(raw), nil
}

func VerifyEd25519(pub ed25519.PublicKey, msg string, sigB64URL string) (bool, error) {
	sig, err := b64urlDecode(sigB64URL)
	if err != nil {
		return false, err
	}
	if len(sig) != ed25519.SignatureSize {
		return false, errors.New("invalid signature size")
	}
	return ed25519.Verify(pub, []byte(msg), sig), nil
}

func SignEd25519(priv ed25519.PrivateKey, msg string) string {
	sig := ed25519.Sign(priv, []byte(msg))
	return b64urlEncode(sig)
}

// DecodeBase64URL decodes a base64url-encoded string (no padding).
func DecodeBase64URL(s string) ([]byte, error) {
	return b64urlDecode(s)
}

// EncodeBase64URL encodes bytes to base64url (no padding).
func EncodeBase64URL(b []byte) string {
	return b64urlEncode(b)
}

// DecodeMultibase decodes a multibase string (currently only base58btc with 'z' prefix).
func DecodeMultibase(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "z") {
		return nil, errors.New("only base58btc multibase (prefix z) supported")
	}
	return base58Decode(s[1:])
}

// VerifyEd25519Bytes verifies an Ed25519 signature with raw bytes.
func VerifyEd25519Bytes(pub []byte, msg []byte, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
