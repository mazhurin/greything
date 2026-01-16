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
