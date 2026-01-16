package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"greything/internal/crypto"
)

type KeyFile struct {
	KID                string `json:"kid"`
	CreatedAt          string `json:"createdAt"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	// ed25519 private key is 64 bytes. Store as base64url (no padding).
	PrivateKeyB64URL   string `json:"privateKeyB64Url"`
}

func main() {
	var out string
	var kid string

	flag.StringVar(&out, "out", "", "Path to write private key JSON (chmod 0600). Required.")
	flag.StringVar(&kid, "kid", "", "Key id, e.g. root or device-2026-01-10. Required.")
	flag.Parse()

	if out == "" || kid == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/gt-keygen --kid <root|device-...> --out <path>")
		os.Exit(2)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	mb := "z" + crypto.Base58Encode(pub)
	privB64 := base64.RawURLEncoding.EncodeToString(priv)

	kf := KeyFile{
		KID:                kid,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		PublicKeyMultibase: mb,
		PrivateKeyB64URL:   privB64,
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		panic(err)
	}

	b, _ := json.MarshalIndent(kf, "", "  ")
	// Write with strict perms. If file exists, overwrite but keep perms strict.
	if err := os.WriteFile(out, b, 0o600); err != nil {
		panic(err)
	}

	fmt.Println("KID:", kid)
	fmt.Println("PublicKeyMultibase:", mb)
	fmt.Println("Saved private key to:", out)
}
