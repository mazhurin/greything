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
	var authorDID string
	var content string
	var postID string
	var out string

	flag.StringVar(&keyPath, "key", "", "Path to device key JSON (from gt-keygen --out). Required.")
	flag.StringVar(&authorDID, "author", "", "Author DID, e.g. did:web:greything.com:users:anton. Required.")
	flag.StringVar(&content, "content", "", "Post content text. Required.")
	flag.StringVar(&postID, "id", "", "Post id (default auto).")
	flag.StringVar(&out, "out", "", "Write output JSON to file (optional).")
	flag.Parse()

	if keyPath == "" || authorDID == "" || content == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/gt-sign-post --key <device-key.json> --author <did> --content <text> [--id <id>] [--out <file>]")
		os.Exit(2)
	}

	kf, priv := mustLoadKeyFile(keyPath)

	createdAt := time.Now().UTC()
	if postID == "" {
		postID = "urn:gt:post:" + createdAt.Format("20060102T150405Z")
	}

	post := types.Post{
		Type:      "Post",
		ID:        postID,
		Author:    authorDID,
		CreatedAt: createdAt,
		Content:   content,
		Signature: types.Signature{
			KID: authorDID + "#" + kf.KID,
			Alg: "Ed25519",
			Sig: "",
		},
	}

	// Sign canonical form
	msg := crypto.CanonicalPost(post)
	post.Signature.Sig = crypto.SignEd25519(priv, msg)

	b, err := json.MarshalIndent(post, "", "  ")
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
		fmt.Println("Wrote signed post to:", out)
		return
	}

	// default: print JSON
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
