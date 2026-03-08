package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"greything/internal/crypto"
)

func TestRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := EncryptRootKey(priv, "my-strong-passphrase", "favorite pet name")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	recovered, err := DecryptRootKey(blob, "my-strong-passphrase")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !pub.Equal(recovered.Public()) {
		t.Fatal("recovered public key does not match original")
	}
	if !priv.Equal(recovered) {
		t.Fatal("recovered private key does not match original")
	}
}

func TestWrongPassphrase(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	blob, err := EncryptRootKey(priv, "correct-passphrase", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptRootKey(blob, "wrong-passphrase")
	if err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestCorruptedCiphertext(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	blob, err := EncryptRootKey(priv, "passphrase", "")
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the ciphertext
	var parsed EncryptedRootKeyV1
	json.Unmarshal(blob, &parsed)
	parsed.CiphertextB64 = "AAAA" + parsed.CiphertextB64[4:]
	corrupted, _ := json.Marshal(parsed)

	_, err = DecryptRootKey(corrupted, "passphrase")
	if err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestPublicKeyInBlob(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	blob, err := EncryptRootKey(priv, "passphrase", "")
	if err != nil {
		t.Fatal(err)
	}

	var parsed EncryptedRootKeyV1
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatal(err)
	}

	expectedMultibase := "z" + crypto.Base58Encode(pub)
	if parsed.PublicKeyMultibase != expectedMultibase {
		t.Fatalf("publicKeyMultibase: got %q, want %q", parsed.PublicKeyMultibase, expectedMultibase)
	}
}

func TestHintStoredInBlob(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	blob, err := EncryptRootKey(priv, "passphrase", "my cat's name")
	if err != nil {
		t.Fatal(err)
	}

	var parsed EncryptedRootKeyV1
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.Hint != "my cat's name" {
		t.Fatalf("hint: got %q, want %q", parsed.Hint, "my cat's name")
	}
}

func TestHintOmittedWhenEmpty(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	blob, err := EncryptRootKey(priv, "passphrase", "")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(blob), `"hint"`) {
		t.Fatal("expected hint to be omitted from JSON when empty")
	}
}

func TestInvalidBlob(t *testing.T) {
	_, err := DecryptRootKey([]byte("not json"), "passphrase")
	if err != ErrInvalidBlob {
		t.Fatalf("expected ErrInvalidBlob, got %v", err)
	}
}

// encryptAESGCM creates an EncryptedRootKeyV1 blob using AES-256-GCM,
// simulating what the browser registration page produces.
func encryptAESGCM(plaintext []byte, pub ed25519.PublicKey, passphrase, hint string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	p := DefaultKDFParams
	key := argon2.IDKey([]byte(passphrase), salt, p.Time, p.Memory, p.Threads, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	blob := EncryptedRootKeyV1{
		Type:               "EncryptedRootKeyV1",
		Alg:                "argon2id+aes256gcm",
		PublicKeyMultibase: "z" + crypto.Base58Encode(pub),
		KDF: KDFParams{
			Alg:     p.Alg,
			Time:    p.Time,
			Memory:  p.Memory,
			Threads: p.Threads,
			SaltB64: base64.StdEncoding.EncodeToString(salt),
		},
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		Hint:          hint,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	return json.Marshal(blob)
}

func TestAESGCMRoundTrip64Bytes(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := encryptAESGCM([]byte(priv), pub, "test-passphrase", "")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	recovered, err := DecryptRootKey(blob, "test-passphrase")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !pub.Equal(recovered.Public()) {
		t.Fatal("recovered public key does not match")
	}
	if !priv.Equal(recovered) {
		t.Fatal("recovered private key does not match")
	}
}

func TestAESGCMSeedOnly(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt only the 32-byte seed (what the browser does)
	seed := priv.Seed()
	blob, err := encryptAESGCM(seed, pub, "browser-pass", "my hint")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	recovered, err := DecryptRootKey(blob, "browser-pass")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !pub.Equal(recovered.Public()) {
		t.Fatal("recovered public key does not match")
	}
	if !priv.Equal(recovered) {
		t.Fatal("recovered private key does not match")
	}
}

func TestAESGCMWrongPassphrase(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	blob, err := encryptAESGCM(priv.Seed(), pub, "correct", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptRootKey(blob, "wrong")
	if err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestBothAlgorithmsDecrypt(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// ChaCha20-Poly1305 (CLI path — encrypts full 64-byte key)
	chachaBlob, err := EncryptRootKey(priv, "same-pass", "")
	if err != nil {
		t.Fatal(err)
	}

	// AES-256-GCM (browser path — encrypts 32-byte seed)
	aesBlob, err := encryptAESGCM(priv.Seed(), pub, "same-pass", "")
	if err != nil {
		t.Fatal(err)
	}

	r1, err := DecryptRootKey(chachaBlob, "same-pass")
	if err != nil {
		t.Fatalf("chacha decrypt: %v", err)
	}

	r2, err := DecryptRootKey(aesBlob, "same-pass")
	if err != nil {
		t.Fatalf("aes decrypt: %v", err)
	}

	if !pub.Equal(r1.Public()) || !pub.Equal(r2.Public()) {
		t.Fatal("public keys don't match")
	}
	if !r1.Equal(r2) {
		t.Fatal("recovered keys differ between algorithms")
	}
}
