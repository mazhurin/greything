package main

import (
	"bufio"
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
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"greything/internal/crypto"
	"greything/internal/did"
	"greything/internal/recovery"
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

type ClaimsManifest struct {
	Version   int               `json:"version"`
	DID       string            `json:"did"`
	Claims    map[string]string `json:"claims"`
	CreatedAt string            `json:"createdAt"`
}

func main() {
	storageURL := flag.String("storage-url", "https://storage.greything.com", "gt-core storage URL")
	didsURL := flag.String("dids-url", "https://did.greything.com", "DIDS server URL")
	didDomain := flag.String("did-domain", "did.greything.com", "DID domain")
	keysDir := flag.String("keys-dir", ".greything/keys", "directory for key files")
	flag.Parse()

	*storageURL = strings.TrimRight(*storageURL, "/")
	*didsURL = strings.TrimRight(*didsURL, "/")

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("=== GreyThing Registration ===")
	fmt.Println()

	// 1. User ID (random, opaque)
	userID := randomID(8)
	didStr := fmt.Sprintf("did:web:%s:u:%s", *didDomain, userID)

	// Check the ID is not taken
	if didExists(*didsURL, userID) {
		fatal("generated ID %s already exists — please try again", userID)
	}
	fmt.Printf("User ID: %s\n", userID)

	// 2. Generate Ed25519 root key
	fmt.Println("Generating root key...")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate key: %v", err)
	}

	pubMultibase := "z" + crypto.Base58Encode(pub)
	privB64 := base64.RawURLEncoding.EncodeToString(priv)

	keyPath := filepath.Join(*keysDir, userID+"-root.json")
	kf := KeyFile{
		KTY:                "Ed25519",
		KID:                "root",
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		PublicKeyMultibase: pubMultibase,
		PrivateKeyB64URL:   privB64,
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		fatal("mkdir: %v", err)
	}
	kfBytes, _ := json.MarshalIndent(kf, "", "  ")
	if err := os.WriteFile(keyPath, kfBytes, 0o600); err != nil {
		fatal("write key: %v", err)
	}
	fmt.Printf("Saved: %s\n", keyPath)

	// 2b. Generate Ed25519 device key (device-1)
	fmt.Println("Generating device key (device-1)...")
	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate device key: %v", err)
	}
	devicePubMultibase := "z" + crypto.Base58Encode(devicePub)
	deviceKeyPath := filepath.Join(*keysDir, userID+"-device-1.json")
	deviceKF := KeyFile{
		KTY:                "Ed25519",
		KID:                "device-1",
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		PublicKeyMultibase: devicePubMultibase,
		PrivateKeyB64URL:   base64.RawURLEncoding.EncodeToString(devicePriv),
	}
	deviceKFBytes, _ := json.MarshalIndent(deviceKF, "", "  ")
	if err := os.WriteFile(deviceKeyPath, deviceKFBytes, 0o600); err != nil {
		fatal("write device key: %v", err)
	}
	fmt.Printf("Saved: %s\n", deviceKeyPath)

	// 2c. Generate X25519 encryption key (x25519-1)
	fmt.Println("Generating encryption key (x25519-1)...")
	xPrivKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate x25519 key: %v", err)
	}
	xPubMultibase := "z" + crypto.Base58Encode(xPrivKey.PublicKey().Bytes())
	xKeyPath := filepath.Join(*keysDir, userID+"-x25519-1.json")
	xKF := KeyFile{
		KTY:                "X25519",
		KID:                "x25519-1",
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
		PublicKeyMultibase: xPubMultibase,
		PrivateKeyB64URL:   base64.RawURLEncoding.EncodeToString(xPrivKey.Bytes()),
	}
	xKFBytes, _ := json.MarshalIndent(xKF, "", "  ")
	if err := os.WriteFile(xKeyPath, xKFBytes, 0o600); err != nil {
		fatal("write x25519 key: %v", err)
	}
	fmt.Printf("Saved: %s\n", xKeyPath)
	fmt.Println()

	// 3. Prompt claims
	fmt.Println("--- Claims (press Enter to skip) ---")
	claims := make(map[string]string)

	type claimPrompt struct {
		display string
		key     string
		isPhone bool
	}
	prompts := []claimPrompt{
		{"Name", "name", false},
		{"Family name", "familyname", false},
		{"Nickname", "nickname", false},
		{"City", "city", false},
		{"Country", "country", false},
		{"Alma mater", "alma_mater", false},
		{"About", "about", false},
		{"Keywords", "keywords", false},
		{"Phone (will be hashed)", "phone", true},
	}

	for _, p := range prompts {
		fmt.Printf("%s: ", p.display)
		val := readLine(scanner)
		if val == "" {
			continue
		}
		if p.isPhone {
			h := sha256.Sum256([]byte(val))
			claims["phone_hash"] = "sha256-" + hex.EncodeToString(h[:])
		} else {
			claims[p.key] = val
		}
	}

	// 4. Custom claims
	fmt.Println()
	fmt.Println("--- Custom claims ---")
	for {
		fmt.Print("Key (empty to finish): ")
		key := readLine(scanner)
		if key == "" {
			break
		}
		fmt.Print("Value: ")
		val := readLine(scanner)
		if val == "" {
			continue
		}
		claims[key] = val
	}
	fmt.Println()

	// 5. Build DID document
	services := map[string]string{
		"pod": fmt.Sprintf("%s/gt/v1/%s", *storageURL, didStr),
	}
	deviceKeys := map[string]string{"device-1": devicePubMultibase}
	deviceXKeys := map[string]string{"x25519-1": xPubMultibase}
	// --- Recovery Setup (recommended) ---
	fmt.Println("--- Recovery Setup (recommended) ---")
	fmt.Println("A recovery passphrase lets you regain access if you lose all devices.")
	fmt.Println("The encrypted key is stored as a public blob — only you can decrypt it.")
	fmt.Println()
	var recoveryPolicy *did.RecoveryPolicy
	var passphrase1 string
	var recoveryHint string
	for {
		fmt.Print("Recovery passphrase (press Enter to skip): ")
		passphrase1 = readLine(scanner)
		if passphrase1 == "" {
			break
		}
		fmt.Printf("Your passphrase: %s\n", passphrase1)
		fmt.Print("Correct? [Y/n]: ")
		confirm := readLine(scanner)
		if confirm == "" || strings.EqualFold(confirm, "y") || strings.EqualFold(confirm, "yes") {
			fmt.Println()
			fmt.Println("Passphrase hint (public! will be visible to anyone):")
			fmt.Println("  Good: \"childhood street + first pet\"")
			fmt.Println("  Bad:  \"fluffy123\" (that's the passphrase itself!)")
			fmt.Print("Hint (press Enter to skip): ")
			recoveryHint = readLine(scanner)
			recoveryPolicy = &did.RecoveryPolicy{
				Type:        "PassphraseEncryptedKey",
				StorageHead: "recovery-key",
				SetAt:       time.Now().UTC().Format(time.RFC3339),
			}
			break
		}
		fmt.Println("Try again.")
		fmt.Println()
	}
	fmt.Println()

	doc := did.Build(didStr, pubMultibase, services, deviceKeys, deviceXKeys, recoveryPolicy)
	docBytes, _ := json.Marshal(doc)
	docHash := hashSHA256(docBytes)

	// 6. Register
	fmt.Printf("Registering %s ...\n", didStr)

	// Step 1: PUT DID to DIDS server
	if err := putDID(*didsURL, userID, didStr, priv, docBytes); err != nil {
		fatal("put DID: %v", err)
	}
	fmt.Println("  ✓ DID document pushed to DIDS")

	// Step 2: PUT DID blob to gt-core
	if err := putBlob(*storageURL, didStr, priv, docHash, docBytes); err != nil {
		fatal("put DID blob: %v", err)
	}

	// Step 3: DIDLog entry (Genesis or Update)
	currentDidlogHead, err := getHead(*storageURL, didStr, "didlog")
	if err != nil && !strings.Contains(err.Error(), "404") {
		fatal("get didlog head: %v", err)
	}

	entry := DIDLogEntry{
		Version:    1,
		DID:        didStr,
		DIDDocHash: docHash,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	expectedDidlog := ""
	if currentDidlogHead == nil {
		entry.Type = "Genesis"
		entry.Prev = ""
	} else {
		entry.Type = "Update"
		entry.Prev = currentDidlogHead.Head
		expectedDidlog = currentDidlogHead.Head
	}

	entryBytes, _ := json.Marshal(entry)
	entryHash := hashSHA256(entryBytes)

	if err := putBlob(*storageURL, didStr, priv, entryHash, entryBytes); err != nil {
		fatal("put didlog blob: %v", err)
	}

	if err := putHead(*storageURL, didStr, priv, "didlog", HeadUpdateRequest{
		Expected: expectedDidlog,
		Head:     entryHash,
	}); err != nil {
		fatal("put didlog head: %v", err)
	}
	fmt.Println("  ✓ DID blob + didlog stored in gt-core")

	// Step 4: Upload encrypted root key (if passphrase was set)
	if recoveryPolicy != nil {
		encBlob, err := recovery.EncryptRootKey(priv, passphrase1, recoveryHint)
		if err != nil {
			fatal("encrypt root key: %v", err)
		}
		encBlobHash := hashSHA256(encBlob)
		if err := putBlob(*storageURL, didStr, priv, encBlobHash, encBlob); err != nil {
			fatal("put encrypted key blob: %v", err)
		}

		currentRecoveryHead, err := getHead(*storageURL, didStr, "recovery-key")
		if err != nil && !strings.Contains(err.Error(), "404") {
			fatal("get recovery-key head: %v", err)
		}
		expectedRecovery := ""
		if currentRecoveryHead != nil {
			expectedRecovery = currentRecoveryHead.Head
		}

		if err := putHead(*storageURL, didStr, priv, "recovery-key", HeadUpdateRequest{
			Expected: expectedRecovery,
			Head:     encBlobHash,
		}); err != nil {
			fatal("put recovery-key head: %v", err)
		}
		fmt.Println("  ✓ Encrypted root key stored in gt-core")
	}

	// Step 5: Claims (if any)
	if len(claims) > 0 {
		manifest := ClaimsManifest{
			Version:   1,
			DID:       didStr,
			Claims:    claims,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		manifestBytes, _ := json.Marshal(manifest)
		manifestHash := hashSHA256(manifestBytes)

		if err := putBlob(*storageURL, didStr, priv, manifestHash, manifestBytes); err != nil {
			fatal("put claims blob: %v", err)
		}

		currentClaimsHead, err := getHead(*storageURL, didStr, "claims")
		if err != nil && !strings.Contains(err.Error(), "404") {
			fatal("get claims head: %v", err)
		}
		expectedClaims := ""
		if currentClaimsHead != nil {
			expectedClaims = currentClaimsHead.Head
		}

		if err := putHead(*storageURL, didStr, priv, "claims", HeadUpdateRequest{
			Expected: expectedClaims,
			Head:     manifestHash,
		}); err != nil {
			fatal("put claims head: %v", err)
		}
		fmt.Println("  ✓ Claims manifest stored in gt-core (reindex auto-triggered)")
	}

	fmt.Println()
	fmt.Printf("Done! Your DID: %s\n", didStr)
	fmt.Printf("Key saved: %s\n", keyPath)
}

func didExists(didsURL, userID string) bool {
	resp, err := http.Get(didsURL + "/u/" + userID + "/did.json")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func readLine(scanner *bufio.Scanner) string {
	if scanner.Scan() {
		return strings.TrimSpace(strings.ToValidUTF8(scanner.Text(), ""))
	}
	return ""
}

func randomID(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
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


