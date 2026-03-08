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

type DIDLogEntry struct {
	Version    int    `json:"version"`
	Type       string `json:"type"` // "Genesis" or "Update"
	DID        string `json:"did"`
	Prev       string `json:"prev"`
	DIDDocHash string `json:"didDocHash"`
	CreatedAt  string `json:"createdAt"`
}

func main() {
	keyPath := flag.String("key", "", "path to root key JSON")
	didStr := flag.String("did", "", "DID to update")
	storageURL := flag.String("storage-url", "", "gt-core storage URL")
	didsURL := flag.String("dids-url", "", "DIDS server URL")
	didDocPath := flag.String("did-doc", "", "path to new did.json")
	flag.Parse()

	if *keyPath == "" || *didStr == "" || *storageURL == "" || *didsURL == "" || *didDocPath == "" {
		fmt.Fprintln(os.Stderr, "usage: gt-did-update --key <path> --did <did> --storage-url <url> --dids-url <url> --did-doc <path>")
		os.Exit(2)
	}

	*storageURL = strings.TrimRight(*storageURL, "/")
	*didsURL = strings.TrimRight(*didsURL, "/")

	// Load private key
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		log.Fatalf("load key: %v", err)
	}

	// Read new did.json
	didDocBytes, err := os.ReadFile(*didDocPath)
	if err != nil {
		log.Fatalf("read did.json: %v", err)
	}

	// Extract user ID from DID
	// did:web:did.greything.com:u:58nekpum → 58nekpum
	parts := strings.Split(*didStr, ":")
	if len(parts) < 5 || parts[3] != "u" {
		log.Fatalf("cannot extract user ID from DID: %s", *didStr)
	}
	userID := parts[4]

	docHash := hashSHA256(didDocBytes)
	log.Printf("did.json hash: %s", docHash)

	// Step 1: PUT did.json to DIDS server (must happen first for new users,
	// because gt-core resolves DID via HTTP for auth)
	err = putDID(*didsURL, userID, *didStr, priv, didDocBytes)
	if err != nil {
		log.Fatalf("put DID to DIDS: %v", err)
	}
	log.Println("pushed did.json to DIDS server")

	// Step 2: PUT did.json blob to gt-core
	err = putBlob(*storageURL, *didStr, priv, docHash, didDocBytes)
	if err != nil {
		log.Fatalf("put blob (did.json): %v", err)
	}
	log.Println("stored did.json blob in gt-core")

	// Step 3: GET current didlog head (may be 404 for Genesis)
	currentHead, err := getHead(*storageURL, *didStr, "didlog")
	if err != nil && !strings.Contains(err.Error(), "404") {
		log.Fatalf("get didlog head: %v", err)
	}

	// Step 4: Create DIDLog entry
	entry := DIDLogEntry{
		Version:    1,
		DID:        *didStr,
		DIDDocHash: docHash,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	if currentHead == nil {
		entry.Type = "Genesis"
		entry.Prev = ""
	} else {
		entry.Type = "Update"
		entry.Prev = currentHead.Head
	}

	entryBytes, _ := json.Marshal(entry)
	entryHash := hashSHA256(entryBytes)
	log.Printf("didlog entry hash: %s (type: %s)", entryHash, entry.Type)

	// Step 5: PUT didlog entry blob to gt-core
	err = putBlob(*storageURL, *didStr, priv, entryHash, entryBytes)
	if err != nil {
		log.Fatalf("put blob (didlog entry): %v", err)
	}
	log.Println("stored didlog entry blob in gt-core")

	// Step 6: CAS update didlog head
	expected := ""
	if currentHead != nil {
		expected = currentHead.Head
	}
	err = putHead(*storageURL, *didStr, priv, "didlog", HeadUpdateRequest{
		Expected: expected,
		Head:     entryHash,
	})
	if err != nil {
		log.Fatalf("update didlog head: %v", err)
	}
	log.Printf("updated didlog head → %s", entryHash)

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
	// hash is "sha256-{hex}", extract hex part
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
		// Already exists — that's fine for content-addressed storage
		return nil
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

func putDID(didsURL, userID, didStr string, priv ed25519.PrivateKey, didDoc []byte) error {
	path := "/api/v1/did/" + userID
	url := didsURL + path

	ts, sig := signAuth(http.MethodPut, path, didDoc, didStr, priv)

	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(didDoc))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GT-DID", didStr)
	req.Header.Set("X-GT-Timestamp", ts)
	req.Header.Set("X-GT-Signature", sig)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PUT DID: %d %s", resp.StatusCode, string(body))
	}
	return nil
}
