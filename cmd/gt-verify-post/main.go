package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"

	"greything/internal/crypto"
	"greything/internal/types"
)

type DIDDoc struct {
	ID                 string `json:"id"`
	VerificationMethod []struct {
		ID                 string `json:"id"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	} `json:"verificationMethod"`
}

func main() {
	var postURL string
	var didURL string

	flag.StringVar(&postURL, "post", "", "URL to post JSON (pod object). Required.")
	flag.StringVar(&didURL, "did", "", "URL to did.json. If empty, inferred from post.author as localhost did-registry.")
	flag.Parse()

	if postURL == "" {
		fmt.Println("usage: go run ./cmd/gt-verify-post --post <url> [--did <did.json url>]")
		return
	}

	post := mustFetchPost(postURL)

	// Infer did.json URL for local prototype if not provided
	if didURL == "" {
		// author DID: did:web:greything.com:users:anton
		author := post.Author
		username := author[strings.LastIndex(author, ":")+1:]
		didURL = "http://localhost:8080/users/" + username + "/did.json"
	}

	doc := mustFetchDIDDoc(didURL)

	pubMB := findPubKeyForKID(doc, post.Signature.KID)
	if pubMB == "" {
		panic("public key for KID not found in DID doc: " + post.Signature.KID)
	}

	if err := crypto.MustAlgEd25519(post.Signature.Alg); err != nil {
		panic(err)
	}

	pub, err := crypto.DecodeMultibaseEd25519Pub(pubMB)
	if err != nil {
		panic(err)
	}

	msg := crypto.CanonicalPost(post)
	ok, err := crypto.VerifyEd25519(pub, msg, post.Signature.Sig)
	if err != nil {
		panic(err)
	}
	if !ok {
		fmt.Println("FAIL: signature invalid")
		return
	}
	fmt.Println("OK: signature valid")
	fmt.Println("Post:", post.ID)
	fmt.Println("Author:", post.Author)
	fmt.Println("KID:", post.Signature.KID)
}

func mustFetchPost(url string) types.Post {
	b := mustFetch(url)
	var p types.Post
	if err := json.Unmarshal(b, &p); err != nil {
		panic(err)
	}
	return p
}

func mustFetchDIDDoc(url string) DIDDoc {
	b := mustFetch(url)
	var d DIDDoc
	if err := json.Unmarshal(b, &d); err != nil {
		panic(err)
	}
	return d
}

func findPubKeyForKID(doc DIDDoc, kid string) string {
	for _, vm := range doc.VerificationMethod {
		if vm.ID == kid {
			return vm.PublicKeyMultibase
		}
	}
	return ""
}

func mustFetch(url string) []byte {
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		panic(fmt.Sprintf("GET %s status %d", url, resp.StatusCode))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return b
}
