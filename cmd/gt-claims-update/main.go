package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"greything/internal/crypto"
)

type KeyFile struct {
	KTY                string `json:"kty"`
	KID                string `json:"kid"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
	PrivateKeyB64URL   string `json:"privateKeyB64Url"`
}

type Head struct {
	Head      string `json:"head"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type HeadUpdateRequest struct {
	Expected string `json:"expected"`
	Head     string `json:"head"`
}

type ClaimsManifest struct {
	Version   int               `json:"version"`
	DID       string            `json:"did"`
	Claims    map[string]string `json:"claims"`
	CreatedAt string            `json:"createdAt"`
}

func main() {
	keyPath := flag.String("key", "", "path to root key JSON")
	didStr := flag.String("did", "", "DID")
	storageURL := flag.String("storage-url", "", "gt-core storage URL")
	didsURL := flag.String("dids-url", "", "DIDS server URL")
	claimsPath := flag.String("claims", "", "path to claims JSON file")
	flag.Parse()

	if *keyPath == "" || *didStr == "" || *storageURL == "" || *didsURL == "" || *claimsPath == "" {
		fmt.Fprintln(os.Stderr, "usage: gt-claims-update --key <path> --did <did> --storage-url <url> --dids-url <url> --claims <path>")
		os.Exit(2)
	}

	*storageURL = strings.TrimRight(*storageURL, "/")
	*didsURL = strings.TrimRight(*didsURL, "/")

	// Load private key
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		log.Fatalf("load key: %v", err)
	}

	// Read claims file
	claimsData, err := os.ReadFile(*claimsPath)
	if err != nil {
		log.Fatalf("read claims: %v", err)
	}

	var claims map[string]string
	if err := json.Unmarshal(claimsData, &claims); err != nil {
		log.Fatalf("parse claims JSON: %v", err)
	}

	// Wrap in manifest
	manifest := ClaimsManifest{
		Version:   1,
		DID:       *didStr,
		Claims:    claims,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	manifestBytes, _ := json.Marshal(manifest)
	manifestHash := hashSHA256(manifestBytes)
	log.Printf("claims manifest hash: %s", manifestHash)

	// Step 1: PUT manifest blob to gt-core
	err = putBlob(*storageURL, *didStr, priv, manifestHash, manifestBytes)
	if err != nil {
		log.Fatalf("put blob: %v", err)
	}
	log.Println("stored claims manifest blob in gt-core")

	// Step 2: GET current claims head
	currentHead, err := getHead(*storageURL, *didStr, "claims")
	if err != nil && !strings.Contains(err.Error(), "404") {
		log.Fatalf("get claims head: %v", err)
	}

	// Step 3: CAS update claims head
	expected := ""
	if currentHead != nil {
		expected = currentHead.Head
	}
	err = putHead(*storageURL, *didStr, priv, "claims", HeadUpdateRequest{
		Expected: expected,
		Head:     manifestHash,
	})
	if err != nil {
		log.Fatalf("update claims head: %v", err)
	}
	log.Printf("updated claims head → %s", manifestHash)

	// Step 4: POST reindex to DIDS server
	err = postReindex(*didsURL, *didStr, priv)
	if err != nil {
		log.Fatalf("reindex: %v", err)
	}
	log.Println("reindex complete")
	log.Println("done!")
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, err
	}
	if kf.KTY != "Ed25519" {
		return nil, fmt.Errorf("expected Ed25519 key, got %s", kf.KTY)
	}
	privBytes, err := base64.RawURLEncoding.DecodeString(kf.PrivateKeyB64URL)
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(privBytes), nil
}

func hashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256-" + hex.EncodeToString(h[:])
}

func signAuth(method, path string, body []byte, didStr string, priv ed25519.PrivateKey) (timestamp, signature string) {
	ts := time.Now().UTC().Format(time.RFC3339)
	h := sha256.Sum256(body)
	bodyHash := "sha256-" + hex.EncodeToString(h[:])
	payload := fmt.Sprintf("%s|%s|%s|%s", ts, method, path, bodyHash)
	sig := crypto.SignEd25519(priv, payload)
	return ts, sig
}

func putBlob(storageURL, didStr string, priv ed25519.PrivateKey, hash string, data []byte) error {
	hexHash := strings.TrimPrefix(hash, "sha256-")
	path := fmt.Sprintf("/gt/v1/%s/blobs/sha256/%s", didStr, hexHash)
	url := storageURL + path

	ts, sig := signAuth(http.MethodPut, path, data, didStr, priv)

	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	req.Header.Set("X-GT-DID", didStr)
	req.Header.Set("X-GT-Timestamp", ts)
	req.Header.Set("X-GT-Signature", sig)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return nil // already exists
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PUT blob: %d %s", resp.StatusCode, string(body))
	}
	return nil
}

func getHead(storageURL, didStr, name string) (*Head, error) {
	url := fmt.Sprintf("%s/gt/v1/%s/heads/%s", storageURL, didStr, name)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("404")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET head: %d %s", resp.StatusCode, string(body))
	}

	var head Head
	if err := json.NewDecoder(resp.Body).Decode(&head); err != nil {
		return nil, err
	}
	return &head, nil
}

func putHead(storageURL, didStr string, priv ed25519.PrivateKey, name string, req HeadUpdateRequest) error {
	path := fmt.Sprintf("/gt/v1/%s/heads/%s", didStr, name)
	url := storageURL + path

	body, _ := json.Marshal(req)
	ts, sig := signAuth(http.MethodPut, path, body, didStr, priv)

	httpReq, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-GT-DID", didStr)
	httpReq.Header.Set("X-GT-Timestamp", ts)
	httpReq.Header.Set("X-GT-Signature", sig)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PUT head: %d %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func postReindex(didsURL, didStr string, priv ed25519.PrivateKey) error {
	// Extract user ID from DID: did:web:did.greything.com:u:58nekpum → 58nekpum
	parts := strings.Split(didStr, ":")
	if len(parts) < 5 || parts[3] != "u" {
		return fmt.Errorf("cannot extract user ID from DID: %s", didStr)
	}
	userID := parts[4]

	path := "/api/v1/did/" + userID + "/reindex"
	body := []byte{}

	ts, sig := signAuth(http.MethodPost, path, body, didStr, priv)

	req, _ := http.NewRequest(http.MethodPost, didsURL+path, nil)
	req.Header.Set("X-GT-DID", didStr)
	req.Header.Set("X-GT-Timestamp", ts)
	req.Header.Set("X-GT-Signature", sig)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST reindex: %d %s", resp.StatusCode, string(respBody))
	}
	return nil
}
