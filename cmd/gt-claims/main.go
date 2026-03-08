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
	"sort"
	"strconv"
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
	keyPath := flag.String("key", "", "path to root key JSON (optional — shows picker if omitted)")
	didStr := flag.String("did", "", "DID (optional — inferred from key filename)")
	storageURL := flag.String("storage-url", "https://storage.greything.com", "gt-core storage URL")
	didsURL := flag.String("dids-url", "https://did.greything.com", "DIDS server URL")
	didDomain := flag.String("did-domain", "did.greything.com", "DID domain")
	keysDir := flag.String("keys-dir", ".greything/keys", "directory for key files")
	flag.Parse()

	*storageURL = strings.TrimRight(*storageURL, "/")
	*didsURL = strings.TrimRight(*didsURL, "/")

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("=== GreyThing Claims Manager ===")
	fmt.Println()

	// 1. Select key
	if *keyPath == "" {
		*keyPath = pickKey(scanner, *keysDir)
	}

	// 2. Load key
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fatal("load key: %v", err)
	}

	// 3. Derive DID
	if *didStr == "" {
		userID := inferUserID(*keyPath)
		if userID == "" {
			fatal("cannot infer user ID from key filename %q — use --did flag", filepath.Base(*keyPath))
		}
		*didStr = fmt.Sprintf("did:web:%s:u:%s", *didDomain, userID)
	}

	userID := extractUserID(*didStr)
	if userID == "" {
		fatal("cannot extract user ID from DID: %s", *didStr)
	}

	fmt.Printf("DID: %s\n", *didStr)
	fmt.Println()

	// 4. Fetch current claims
	claims, currentHeadHash := fetchClaims(*storageURL, *didStr)
	if claims == nil {
		claims = make(map[string]string)
	}
	original := copyMap(claims)
	dirty := false

	// 5. Interactive loop
	for {
		showClaims(claims)
		fmt.Println()
		fmt.Print("[a]dd  [e]dit  [d]elete  [s]ave & push  [q]uit\n> ")
		cmd := readLine(scanner)

		switch strings.ToLower(cmd) {
		case "a":
			fmt.Print("Key: ")
			key := readLine(scanner)
			if key == "" {
				continue
			}
			fmt.Print("Value: ")
			val := readLine(scanner)
			if val == "" {
				continue
			}
			// Auto-detect phone
			if isPhoneLike(val) {
				fmt.Print("→ Detected phone-like value, store as phone_hash? [Y/n]: ")
				ans := readLine(scanner)
				if ans == "" || strings.ToLower(ans) == "y" {
					h := sha256.Sum256([]byte(val))
					claims["phone_hash"] = "sha256-" + hex.EncodeToString(h[:])
					dirty = true
					continue
				}
			}
			claims[key] = val
			dirty = true

		case "e":
			keys := sortedKeys(claims)
			if len(keys) == 0 {
				fmt.Println("No claims to edit.")
				continue
			}
			fmt.Printf("Edit which claim? [1-%d]: ", len(keys))
			numStr := readLine(scanner)
			idx, err := strconv.Atoi(numStr)
			if err != nil || idx < 1 || idx > len(keys) {
				fmt.Println("Invalid choice.")
				continue
			}
			key := keys[idx-1]
			fmt.Printf("New value for %s [%s]: ", key, claims[key])
			val := readLine(scanner)
			if val == "" {
				continue
			}
			claims[key] = val
			dirty = true

		case "d":
			keys := sortedKeys(claims)
			if len(keys) == 0 {
				fmt.Println("No claims to delete.")
				continue
			}
			fmt.Printf("Delete which claim? [1-%d]: ", len(keys))
			numStr := readLine(scanner)
			idx, err := strconv.Atoi(numStr)
			if err != nil || idx < 1 || idx > len(keys) {
				fmt.Println("Invalid choice.")
				continue
			}
			key := keys[idx-1]
			fmt.Printf("Delete %s = %s? [y/N]: ", key, claims[key])
			ans := readLine(scanner)
			if strings.ToLower(ans) == "y" {
				delete(claims, key)
				dirty = true
			}

		case "s":
			if !dirty {
				fmt.Println("No changes to save.")
				continue
			}
			saveClaims(*storageURL, *didStr, priv, claims, currentHeadHash)
			dirty = false
			original = copyMap(claims)
			// Update head hash for next CAS
			h, err := getHead(*storageURL, *didStr, "claims")
			if err == nil {
				currentHeadHash = h.Head
			}

		case "q":
			if dirty {
				fmt.Print("Unsaved changes! Quit anyway? [y/N]: ")
				ans := readLine(scanner)
				if strings.ToLower(ans) != "y" {
					continue
				}
			}
			_ = original
			return

		default:
			fmt.Println("Unknown command. Use a/e/d/s/q.")
		}
	}
}

func pickKey(scanner *bufio.Scanner, keysDir string) string {
	matches, err := filepath.Glob(filepath.Join(keysDir, "*.json"))
	if err != nil || len(matches) == 0 {
		fatal("no key files found in %s", keysDir)
	}

	fmt.Println("Select key:")
	for i, m := range matches {
		fmt.Printf("  [%d] %s\n", i+1, filepath.Base(m))
	}

	fmt.Printf("Choice [1]: ")
	choice := readLine(scanner)
	idx := 1
	if choice != "" {
		var err error
		idx, err = strconv.Atoi(choice)
		if err != nil || idx < 1 || idx > len(matches) {
			fatal("invalid choice")
		}
	}
	fmt.Println()
	return matches[idx-1]
}

func inferUserID(keyPath string) string {
	base := filepath.Base(keyPath)
	// Pattern: {userID}-root.json
	if strings.HasSuffix(base, "-root.json") {
		return strings.TrimSuffix(base, "-root.json")
	}
	return ""
}

func extractUserID(didStr string) string {
	parts := strings.Split(didStr, ":")
	if len(parts) >= 5 && parts[3] == "u" {
		return parts[4]
	}
	return ""
}

func fetchClaims(storageURL, didStr string) (map[string]string, string) {
	head, err := getHead(storageURL, didStr, "claims")
	if err != nil {
		return nil, ""
	}

	// Fetch the blob
	blobData, err := getBlob(storageURL, didStr, head.Head)
	if err != nil {
		fmt.Printf("Warning: could not fetch claims blob: %v\n", err)
		return nil, head.Head
	}

	var manifest ClaimsManifest
	if err := json.Unmarshal(blobData, &manifest); err != nil {
		fmt.Printf("Warning: could not parse claims manifest: %v\n", err)
		return nil, head.Head
	}

	return manifest.Claims, head.Head
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

func showClaims(claims map[string]string) {
	keys := sortedKeys(claims)
	if len(keys) == 0 {
		fmt.Println("Current claims: (none)")
		return
	}
	fmt.Println("Current claims:")
	for i, k := range keys {
		fmt.Printf("  %d. %s = %s\n", i+1, k, claims[k])
	}
}

func saveClaims(storageURL, didStr string, priv ed25519.PrivateKey, claims map[string]string, expectedHead string) {
	manifest := ClaimsManifest{
		Version:   1,
		DID:       didStr,
		Claims:    claims,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	manifestBytes, _ := json.Marshal(manifest)
	manifestHash := hashSHA256(manifestBytes)

	if err := putBlob(storageURL, didStr, priv, manifestHash, manifestBytes); err != nil {
		fmt.Printf("  ✗ Error storing claims blob: %v\n", err)
		return
	}

	if err := putHead(storageURL, didStr, priv, "claims", HeadUpdateRequest{
		Expected: expectedHead,
		Head:     manifestHash,
	}); err != nil {
		fmt.Printf("  ✗ Error updating claims head: %v\n", err)
		return
	}
	fmt.Println("  ✓ Claims manifest stored in gt-core (reindex auto-triggered)")
	fmt.Println("Done!")
}

func isPhoneLike(val string) bool {
	if len(val) < 7 {
		return false
	}
	cleaned := strings.ReplaceAll(val, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	if strings.HasPrefix(cleaned, "+") {
		cleaned = cleaned[1:]
	}
	for _, c := range cleaned {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func copyMap(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func readLine(scanner *bufio.Scanner) string {
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

// --- HTTP helpers (same patterns as other gt-* tools) ---

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


