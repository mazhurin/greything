package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"greything/internal/crypto"
	"greything/internal/types"
)

type KeyFile struct {
	KID                string `json:"kid"`
	CreatedAt          string `json:"createdAt"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	PrivateKeyB64URL   string `json:"privateKeyB64Url"`
}

func main() {
	var keyPath string
	var actorDID string
	var objectURL string
	var eventType string
	var out string

	flag.StringVar(&keyPath, "key", "", "Path to device key JSON (from gt-keygen --out). Required.")
	flag.StringVar(&actorDID, "actor", "", "Actor DID, e.g. did:web:greything.com:users:anton. Required.")
	flag.StringVar(&objectURL, "object", "", "Object URL (pod object URL). Required.")
	flag.StringVar(&eventType, "type", "new_post", "Event type (default: new_post).")
	flag.StringVar(&out, "out", "", "Write output JSON to file (optional).")
	flag.Parse()

	if keyPath == "" || actorDID == "" || objectURL == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/gt-sign-event --key <device-key.json> --actor <did> --object <url> [--type new_post] [--out <file>]")
		os.Exit(2)
	}

	kf, priv := mustLoadKeyFile(keyPath)

	e := types.Event{
		Type:      eventType,
		Actor:     actorDID,
		ObjectURL: objectURL,
		TS:        time.Now().UTC(),
		Signature: types.Signature{
			KID: actorDID + "#" + kf.KID,
			Alg: "Ed25519",
			Sig: "",
		},
	}

	msg := crypto.CanonicalEvent(e)
	e.Signature.Sig = crypto.SignEd25519(priv, msg)

	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		panic(err)
	}

	if out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(out, b, 0o644); err != nil {
			panic(err)
		}
		fmt.Println("Wrote signed event to:", out)
		return
	}

	fmt.Println(string(b))
}

func mustLoadKeyFile(path string) (KeyFile, ed25519.PrivateKey) {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var kf KeyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		panic(err)
	}
	if kf.KID == "" || kf.PrivateKeyB64URL == "" {
		panic("invalid key file: missing kid or privateKeyB64Url")
	}
	privBytes, err := base64.RawURLEncoding.DecodeString(kf.PrivateKeyB64URL)
	if err != nil {
		panic(err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		panic("invalid private key size (expected 64 bytes for ed25519)")
	}
	return kf, ed25519.PrivateKey(privBytes)
}
