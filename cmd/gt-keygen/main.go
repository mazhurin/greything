package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"greything/internal/crypto"
)

type KeyFile struct {
	KTY                string `json:"kty"` // "X25519" or "Ed25519"
	KID                string `json:"kid"`
	CreatedAt          string `json:"createdAt"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	PrivateKeyB64URL   string `json:"privateKeyB64Url"`
}

func main() {
	var out string
	var kid string
	var kty string

	flag.StringVar(&out, "out", "", "Path to write private key JSON (chmod 0600). Required.")
	flag.StringVar(&kid, "kid", "", "Key id, e.g. root or device-2026-01-10 or x25519-2026-01-21. Required.")
	flag.StringVar(&kty, "kty", "x25519", "Key type: x25519 or ed25519. Default x25519.")
	flag.Parse()

	if out == "" || kid == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/gt-keygen --kty <x25519|ed25519> --kid <...> --out <path>")
		os.Exit(2)
	}

	kty = strings.ToLower(strings.TrimSpace(kty))

	var pubBytes []byte
	var privBytes []byte
	var outKTY string

	switch kty {
	case "x25519":
		outKTY = "X25519"
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pubBytes = priv.PublicKey().Bytes() // 32
		privBytes = priv.Bytes()            // 32

	case "ed25519":
		outKTY = "Ed25519"
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		pubBytes = pub              // 32
		privBytes = priv            // 64 (expanded private key)

	default:
		fmt.Fprintln(os.Stderr, "unknown --kty, use x25519 or ed25519")
		os.Exit(2)
	}

	mb := "z" + crypto.Base58Encode(pubBytes)
	privB64 := base64.RawURLEncoding.EncodeToString(privBytes)

	kf := KeyFile{
		KTY:                outKTY,
		KID:                kid,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		PublicKeyMultibase: mb,
		PrivateKeyB64URL:   privB64,
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		panic(err)
	}

	b, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.WriteFile(out, b, 0o600); err != nil {
		panic(err)
	}

	fmt.Println("KTY:", outKTY)
	fmt.Println("KID:", kid)
	fmt.Println("PublicKeyMultibase:", mb)
	fmt.Println("Saved private key to:", out)
}
