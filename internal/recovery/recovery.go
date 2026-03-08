package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"greything/internal/crypto"
)

var (
	ErrDecryptFailed = errors.New("decryption failed: wrong passphrase or corrupted data")
	ErrInvalidBlob   = errors.New("invalid encrypted key blob")
)

type KDFParams struct {
	Alg     string `json:"alg"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	SaltB64 string `json:"saltB64"`
}

type EncryptedRootKeyV1 struct {
	Type               string    `json:"type"`
	Alg                string    `json:"alg"`
	PublicKeyMultibase string    `json:"publicKeyMultibase"`
	KDF                KDFParams `json:"kdf"`
	NonceB64           string    `json:"nonceB64"`
	CiphertextB64      string    `json:"ciphertextB64"`
	Hint               string    `json:"hint,omitempty"`
	CreatedAt          string    `json:"createdAt"`
}

var DefaultKDFParams = KDFParams{
	Alg:     "argon2id",
	Time:    3,
	Memory:  65536, // 64 MB
	Threads: 4,
}

// EncryptRootKey encrypts an Ed25519 private key with a passphrase using
// Argon2id key derivation and ChaCha20-Poly1305 encryption.
func EncryptRootKey(priv ed25519.PrivateKey, passphrase, hint string) ([]byte, error) {
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Derive key with Argon2id
	p := DefaultKDFParams
	key := argon2.IDKey([]byte(passphrase), salt, p.Time, p.Memory, p.Threads, 32)

	// Encrypt with ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(priv), nil)

	pub := priv.Public().(ed25519.PublicKey)
	pubMultibase := "z" + crypto.Base58Encode(pub)

	blob := EncryptedRootKeyV1{
		Type:               "EncryptedRootKeyV1",
		Alg:                "argon2id+chacha20poly1305",
		PublicKeyMultibase: pubMultibase,
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

// DecryptRootKey decrypts an encrypted root key blob using the given passphrase.
// It verifies that the decrypted key's public key matches the publicKeyMultibase in the blob.
func DecryptRootKey(blobJSON []byte, passphrase string) (ed25519.PrivateKey, error) {
	var blob EncryptedRootKeyV1
	if err := json.Unmarshal(blobJSON, &blob); err != nil {
		return nil, ErrInvalidBlob
	}

	if blob.Type != "EncryptedRootKeyV1" {
		return nil, ErrInvalidBlob
	}

	salt, err := base64.StdEncoding.DecodeString(blob.KDF.SaltB64)
	if err != nil {
		return nil, ErrInvalidBlob
	}

	nonce, err := base64.StdEncoding.DecodeString(blob.NonceB64)
	if err != nil {
		return nil, ErrInvalidBlob
	}

	ciphertext, err := base64.StdEncoding.DecodeString(blob.CiphertextB64)
	if err != nil {
		return nil, ErrInvalidBlob
	}

	// Derive key with Argon2id
	key := argon2.IDKey([]byte(passphrase), salt, blob.KDF.Time, blob.KDF.Memory, blob.KDF.Threads, 32)

	// Decrypt based on algorithm
	var aead cipher.AEAD
	switch blob.Alg {
	case "argon2id+chacha20poly1305":
		aead, err = chacha20poly1305.New(key)
	case "argon2id+aes256gcm":
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidBlob, blob.Alg)
	}
	if err != nil {
		return nil, ErrDecryptFailed
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	// Handle both 64-byte full key (CLI) and 32-byte seed (browser)
	var priv ed25519.PrivateKey
	switch len(plaintext) {
	case ed25519.PrivateKeySize: // 64 bytes — full Go private key
		priv = ed25519.PrivateKey(plaintext)
	case ed25519.SeedSize: // 32 bytes — seed only (browser)
		priv = ed25519.NewKeyFromSeed(plaintext)
	default:
		return nil, ErrDecryptFailed
	}

	// Verify public key matches
	pub := priv.Public().(ed25519.PublicKey)
	expectedMultibase := "z" + crypto.Base58Encode(pub)
	if expectedMultibase != blob.PublicKeyMultibase {
		return nil, ErrDecryptFailed
	}

	return priv, nil
}
