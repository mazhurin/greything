package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"greything/internal/crypto"
	"greything/internal/did"
)

type KeyFile struct {
	KTY                string `json:"kty"`
	KID                string `json:"kid"`
	CreatedAt          string `json:"createdAt"`
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
	Type       string `json:"type"`
	DID        string `json:"did"`
	Prev       string `json:"prev"`
	DIDDocHash string `json:"didDocHash"`
	CreatedAt  string `json:"createdAt"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	cmd := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	switch cmd {
	case "add":
		cmdAdd()
	case "revoke":
		cmdRevoke()
	case "list":
		cmdList()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gt-device-key <add|revoke|list> [flags]")
	os.Exit(2)
}

func cmdAdd() {
	keyPath := flag.String("key", "", "path to signing key JSON (root or device)")
	didStr := flag.String("did", "", "DID to update")
	storageURL := flag.String("storage-url", "https://storage.greything.com", "gt-core storage URL")
	didsURL := flag.String("dids-url", "https://did.greything.com", "DIDS server URL")
	name := flag.String("name", "", "name for new device key (e.g. myphone)")
	keyType := flag.String("type", "ed25519", "key type: ed25519 or x25519")
	keysDir := flag.String("keys-dir", ".greything/keys", "directory for key files")
	flag.Parse()

	if *keyPath == "" || *didStr == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "usage: gt-device-key add --key <path> --did <did> --name <name> [--type ed25519|x25519]")
		os.Exit(2)
	}

	*storageURL = strings.TrimRight(*storageURL, "/")
	*didsURL = strings.TrimRight(*didsURL, "/")

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fatal("load key: %v", err)
	}

	userID := extractUserID(*didStr)

	// Fetch current DID doc
	currentDoc, err := fetchDIDDoc(*didsURL, userID)
	if err != nil {
		fatal("fetch DID doc: %v", err)
	}

	rootPub, services, deviceKeys, deviceXKeys, existingPolicy := did.ParseDocument(*currentDoc)

	// Generate new key
	var newPubMultibase string
	switch strings.ToLower(*keyType) {
	case "ed25519":
		pub, newPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fatal("generate key: %v", err)
		}
		newPubMultibase = "z" + crypto.Base58Encode(pub)
		saveKey(*keysDir, userID, *name, "Ed25519", newPubMultibase, newPriv)
		deviceKeys[*name] = newPubMultibase
	case "x25519":
		xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			fatal("generate key: %v", err)
		}
		newPubMultibase = "z" + crypto.Base58Encode(xPriv.PublicKey().Bytes())
		saveKey(*keysDir, userID, *name, "X25519", newPubMultibase, xPriv.Bytes())
		deviceXKeys[*name] = newPubMultibase
	default:
		fatal("unknown key type: %s (use ed25519 or x25519)", *keyType)
	}

	// Rebuild and push
	newDoc := did.Build(*didStr, rootPub, services, deviceKeys, deviceXKeys, existingPolicy)
	pushDIDUpdate(*didsURL, *storageURL, *didStr, userID, priv, newDoc)

	fmt.Printf("Added %s key '%s' to %s\n", *keyType, *name, *didStr)
}

func cmdRevoke() {
	keyPath := flag.String("key", "", "path to signing key JSON (root or device)")
	didStr := flag.String("did", "", "DID to update")
	storageURL := flag.String("storage-url", "https://storage.greything.com", "gt-core storage URL")
	didsURL := flag.String("dids-url", "https://did.greything.com", "DIDS server URL")
	name := flag.String("name", "", "name of device key to revoke")
	flag.Parse()

	if *keyPath == "" || *didStr == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "usage: gt-device-key revoke --key <path> --did <did> --name <name>")
		os.Exit(2)
	}

	*storageURL = strings.TrimRight(*storageURL, "/")
	*didsURL = strings.TrimRight(*didsURL, "/")

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fatal("load key: %v", err)
	}

	userID := extractUserID(*didStr)

	currentDoc, err := fetchDIDDoc(*didsURL, userID)
	if err != nil {
		fatal("fetch DID doc: %v", err)
	}

	rootPub, services, deviceKeys, deviceXKeys, existingPolicy := did.ParseDocument(*currentDoc)

	// Remove key
	_, inEd := deviceKeys[*name]
	_, inX := deviceXKeys[*name]
	if !inEd && !inX {
		fatal("key '%s' not found in DID document", *name)
	}
	delete(deviceKeys, *name)
	delete(deviceXKeys, *name)

	newDoc := did.Build(*didStr, rootPub, services, deviceKeys, deviceXKeys, existingPolicy)
	pushDIDUpdate(*didsURL, *storageURL, *didStr, userID, priv, newDoc)

	fmt.Printf("Revoked key '%s' from %s\n", *name, *didStr)
}

func cmdList() {
	didStr := flag.String("did", "", "DID to list keys for")
	didsURL := flag.String("dids-url", "https://did.greything.com", "DIDS server URL")
	flag.Parse()

	if *didStr == "" {
		fmt.Fprintln(os.Stderr, "usage: gt-device-key list --did <did>")
		os.Exit(2)
	}

	*didsURL = strings.TrimRight(*didsURL, "/")
	userID := extractUserID(*didStr)

	doc, err := fetchDIDDoc(*didsURL, userID)
	if err != nil {
		fatal("fetch DID doc: %v", err)
	}

	fmt.Printf("Keys for %s:\n", *didStr)
	for _, vm := range doc.VerificationMethod {
		fragment := vm.ID
		if idx := strings.LastIndex(fragment, "#"); idx >= 0 {
			fragment = fragment[idx+1:]
		}
		role := ""
		if fragment == "root" {
			role = " (root)"
		}
		fmt.Printf("  %-20s %s%s\n", fragment, vm.Type, role)
	}
}

// --- helpers ---

func extractUserID(didStr string) string {
	parts := strings.Split(didStr, ":")
	if len(parts) < 5 || parts[3] != "u" {
		fatal("cannot extract user ID from DID: %s", didStr)
	}
	return parts[4]
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

func saveKey(keysDir, userID, name, kty, pubMultibase string, privBytes []byte) {
	kf := KeyFile{
		KTY:                kty,
		KID:                name,
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		PublicKeyMultibase: pubMultibase,
		PrivateKeyB64URL:   base64.RawURLEncoding.EncodeToString(privBytes),
	}
	path := filepath.Join(keysDir, userID+"-"+name+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatal("mkdir: %v", err)
	}
	data, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fatal("write key: %v", err)
	}
	fmt.Printf("Saved key: %s\n", path)
}

func fetchDIDDoc(didsURL, userID string) (*did.DIDDocument, error) {
	resp, err := http.Get(didsURL + "/u/" + userID + "/did.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET did.json: %d %s", resp.StatusCode, string(body))
	}
	var doc did.DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func pushDIDUpdate(didsURL, storageURL, didStr, userID string, priv ed25519.PrivateKey, doc did.DIDDocument) {
	docBytes, _ := json.Marshal(doc)
	docHash := hashSHA256(docBytes)

	// PUT DID to DIDS server
	if err := putDID(didsURL, userID, didStr, priv, docBytes); err != nil {
		fatal("put DID: %v", err)
	}
	fmt.Println("  pushed did.json to DIDS")

	// PUT blob
	if err := putBlob(storageURL, didStr, priv, docHash, docBytes); err != nil {
		fatal("put blob: %v", err)
	}

	// DIDLog entry
	currentHead, err := getHead(storageURL, didStr, "didlog")
	if err != nil && !strings.Contains(err.Error(), "404") {
		fatal("get didlog head: %v", err)
	}

	entry := DIDLogEntry{
		Version:    1,
		DID:        didStr,
		DIDDocHash: docHash,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	expected := ""
	if currentHead == nil {
		entry.Type = "Genesis"
	} else {
		entry.Type = "Update"
		entry.Prev = currentHead.Head
		expected = currentHead.Head
	}

	entryBytes, _ := json.Marshal(entry)
	entryHash := hashSHA256(entryBytes)

	if err := putBlob(storageURL, didStr, priv, entryHash, entryBytes); err != nil {
		fatal("put didlog blob: %v", err)
	}

	if err := putHead(storageURL, didStr, priv, "didlog", HeadUpdateRequest{
		Expected: expected,
		Head:     entryHash,
	}); err != nil {
		fatal("put didlog head: %v", err)
	}
	fmt.Println("  stored blob + didlog in gt-core")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
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
