package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
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

	"golang.org/x/term"

	"greything/internal/crypto"
	"greything/internal/did"
	"greything/internal/recovery"
)

var scanner = bufio.NewScanner(os.Stdin)

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
	case "setup":
		cmdSetup()
	case "recover":
		cmdRecover()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gt-recovery <setup|recover> [flags]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  setup    — set or rotate recovery passphrase (requires root key)")
	fmt.Fprintln(os.Stderr, "  recover  — recover root key from passphrase")
	os.Exit(2)
}

func cmdSetup() {
	keyPath := flag.String("key", "", "path to root key JSON")
	didStr := flag.String("did", "", "DID to set recovery for")
	storageURL := flag.String("storage-url", "https://storage.greything.com", "gt-core storage URL")
	didsURL := flag.String("dids-url", "https://did.greything.com", "DIDS server URL")
	flag.Parse()

	if *keyPath == "" || *didStr == "" {
		fmt.Fprintln(os.Stderr, "usage: gt-recovery setup --key <root-key.json> --did <did> [--storage-url ...] [--dids-url ...]")
		os.Exit(2)
	}

	*storageURL = strings.TrimRight(*storageURL, "/")
	*didsURL = strings.TrimRight(*didsURL, "/")

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fatal("load key: %v", err)
	}

	// Prompt passphrase (no-echo)
	var pass1 []byte
	var hint string
	for {
		fmt.Print("Recovery passphrase: ")
		p1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fatal("read passphrase: %v", err)
		}
		if len(p1) == 0 {
			fatal("passphrase cannot be empty")
		}

		fmt.Print("Confirm passphrase: ")
		p2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fatal("read passphrase: %v", err)
		}

		if string(p1) == string(p2) {
			pass1 = p1
			break
		}
		fmt.Println("Passphrases do not match, try again.")
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("Passphrase hint (public! will be visible to anyone):")
	fmt.Println("  Good: \"childhood street + first pet\"")
	fmt.Println("  Bad:  \"fluffy123\" (that's the passphrase itself!)")
	fmt.Print("Hint (press Enter to skip): ")
	hint = readLine()
	fmt.Println()

	userID := extractUserID(*didStr)

	// Encrypt root key
	encBlob, err := recovery.EncryptRootKey(priv, string(pass1), hint)
	if err != nil {
		fatal("encrypt root key: %v", err)
	}
	encBlobHash := hashSHA256(encBlob)

	// Upload blob
	if err := putBlob(*storageURL, *didStr, priv, encBlobHash, encBlob); err != nil {
		fatal("put encrypted key blob: %v", err)
	}

	// Update recovery-key head
	currentHead, err := getHead(*storageURL, *didStr, "recovery-key")
	if err != nil && !strings.Contains(err.Error(), "404") {
		fatal("get recovery-key head: %v", err)
	}
	expected := ""
	if currentHead != nil {
		expected = currentHead.Head
	}

	if err := putHead(*storageURL, *didStr, priv, "recovery-key", HeadUpdateRequest{
		Expected: expected,
		Head:     encBlobHash,
	}); err != nil {
		fatal("put recovery-key head: %v", err)
	}
	fmt.Println("Encrypted root key stored in gt-core")

	// Update DID document with recovery policy
	currentDoc, err := fetchDIDDoc(*didsURL, userID)
	if err != nil {
		fatal("fetch DID doc: %v", err)
	}

	rootPub, services, deviceKeys, deviceXKeys, _ := did.ParseDocument(*currentDoc)
	policy := &did.RecoveryPolicy{
		Type:        "PassphraseEncryptedKey",
		StorageHead: "recovery-key",
		SetAt:       time.Now().UTC().Format(time.RFC3339),
	}
	newDoc := did.Build(*didStr, rootPub, services, deviceKeys, deviceXKeys, policy)
	pushDIDUpdate(*didsURL, *storageURL, *didStr, userID, priv, newDoc)

	fmt.Println("Recovery policy set in DID document")
	fmt.Println("Done!")
}

func cmdRecover() {
	didStr := flag.String("did", "", "DID to recover")
	storageURL := flag.String("storage-url", "https://storage.greything.com", "gt-core storage URL")
	didsURL := flag.String("dids-url", "https://did.greything.com", "DIDS server URL")
	keysDir := flag.String("keys-dir", ".greything/keys", "directory to save recovered key")
	flag.Parse()

	if *didStr == "" {
		fmt.Fprintln(os.Stderr, "usage: gt-recovery recover --did <did> [--storage-url ...] [--dids-url ...] [--keys-dir ...]")
		os.Exit(2)
	}

	*storageURL = strings.TrimRight(*storageURL, "/")
	*didsURL = strings.TrimRight(*didsURL, "/")

	userID := extractUserID(*didStr)

	// 1. Fetch DID doc → recoveryPolicy
	doc, err := fetchDIDDoc(*didsURL, userID)
	if err != nil {
		fatal("fetch DID doc: %v", err)
	}

	if doc.RecoveryPolicy == nil {
		fatal("DID document has no recovery policy")
	}

	headName := doc.RecoveryPolicy.StorageHead
	if headName == "" {
		fatal("recovery policy has no storageHead")
	}

	// 2. GET recovery-key head → blob hash
	head, err := getHead(*storageURL, *didStr, headName)
	if err != nil {
		fatal("get %s head: %v", headName, err)
	}

	// 3. GET blob (public, no auth needed)
	blobData, err := getBlob(*storageURL, *didStr, head.Head)
	if err != nil {
		fatal("get encrypted key blob: %v", err)
	}

	// Show hint if available
	var encBlob recovery.EncryptedRootKeyV1
	if json.Unmarshal(blobData, &encBlob) == nil && encBlob.Hint != "" {
		fmt.Printf("Hint: %s\n", encBlob.Hint)
	}

	// 4. Prompt passphrase (no-echo)
	fmt.Print("Recovery passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal("read passphrase: %v", err)
	}

	// 5. Decrypt
	priv, err := recovery.DecryptRootKey(blobData, string(pass))
	if err != nil {
		fatal("decrypt: %v", err)
	}

	// 6. Save to keys dir
	pub := priv.Public().(ed25519.PublicKey)
	pubMultibase := "z" + crypto.Base58Encode(pub)

	if err := os.MkdirAll(*keysDir, 0o755); err != nil {
		fatal("mkdir: %v", err)
	}

	kf := KeyFile{
		KTY:                "Ed25519",
		KID:                "root",
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		PublicKeyMultibase: pubMultibase,
		PrivateKeyB64URL:   base64.RawURLEncoding.EncodeToString(priv),
	}
	kfBytes, _ := json.MarshalIndent(kf, "", "  ")
	outPath := filepath.Join(*keysDir, userID+"-root.json")
	if err := os.WriteFile(outPath, kfBytes, 0o600); err != nil {
		fatal("write key: %v", err)
	}

	fmt.Printf("Recovered root key saved: %s\n", outPath)
	fmt.Printf("Public key: %s\n", pubMultibase)
}

// --- helpers ---

func readLine() string {
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

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

func getBlob(storageURL, didStr, hash string) ([]byte, error) {
	hexHash := strings.TrimPrefix(hash, "sha256-")
	url := fmt.Sprintf("%s/gt/v1/%s/blobs/sha256/%s", storageURL, didStr, hexHash)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET blob: %d %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func pushDIDUpdate(didsURL, storageURL, didStr, userID string, priv ed25519.PrivateKey, doc did.DIDDocument) {
	docBytes, _ := json.Marshal(doc)
	docHash := hashSHA256(docBytes)

	if err := putDID(didsURL, userID, didStr, priv, docBytes); err != nil {
		fatal("put DID: %v", err)
	}

	if err := putBlob(storageURL, didStr, priv, docHash, docBytes); err != nil {
		fatal("put blob: %v", err)
	}

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
