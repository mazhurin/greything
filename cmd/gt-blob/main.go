package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"greything/internal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "upload":
		cmdUpload(args)
	case "download":
		cmdDownload(args)
	case "meta":
		cmdMeta(args)
	case "delete":
		cmdDelete(args)
	case "hash":
		cmdHash(args)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gt-blob - GreyThing Storage CLI

Usage:
  gt-blob hash <file>                    Compute hash of file
  gt-blob upload <file> [options]        Upload file to storage
  gt-blob download <hash> [options]      Download file from storage
  gt-blob meta <hash> [options]          Get metadata for hash
  gt-blob delete <hash> [options]        Delete blob from storage

Options:
  --key <path>       Path to private key JSON file
  --storage <url>    Storage API URL (default: https://storage.greything.com)
  --acl <dids>       Comma-separated list of DIDs for ACL (default: * for public)
  --type <mime>      Content type (default: auto-detect)
  --out <path>       Output file path (for download)
  --hot/--cold       Storage tier (default: hot)

Examples:
  gt-blob hash photo.jpg
  gt-blob upload photo.jpg --key ~/.greything/keys/device.json --acl "*"
  gt-blob download sha256-abc123 --key ~/.greything/keys/device.json --out photo.jpg
  gt-blob meta sha256-abc123 --key ~/.greything/keys/device.json
`)
}

func cmdHash(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: gt-blob hash <file>")
		os.Exit(1)
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	hash := computeHash(data)
	fmt.Println(hash)
}

func cmdUpload(args []string) {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	keyPath := fs.String("key", "", "Path to private key JSON")
	didOverride := fs.String("did", "", "DID to use (overrides key file)")
	storageURL := fs.String("storage", "https://storage.greything.com", "Storage API URL")
	acl := fs.String("acl", "*", "ACL (comma-separated DIDs, or * for public)")
	contentType := fs.String("type", "", "Content type")
	cold := fs.Bool("cold", false, "Use cold storage")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: gt-blob upload <file> --key <path>")
		os.Exit(1)
	}
	filePath := fs.Arg(0)

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --key is required")
		os.Exit(1)
	}

	// Load key
	key, err := loadKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}

	// Override DID if specified
	if *didOverride != "" {
		key.DID = *didOverride
	}
	if key.DID == "" {
		fmt.Fprintln(os.Stderr, "Error: DID not found in key file, use --did")
		os.Exit(1)
	}
	fmt.Printf("DID: %s\n", key.DID)

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	hash := computeHash(data)
	fmt.Printf("Hash: %s\n", hash)
	fmt.Printf("Size: %d bytes\n", len(data))

	// Detect content type
	ct := *contentType
	if ct == "" {
		ct = detectContentType(filePath, data)
	}
	fmt.Printf("Content-Type: %s\n", ct)

	// Parse ACL
	var aclList []string
	if *acl == "" || *acl == "[]" {
		aclList = []string{}
	} else if *acl == "*" {
		aclList = []string{"*"}
	} else {
		aclList = strings.Split(*acl, ",")
	}

	storage := "hot"
	if *cold {
		storage = "cold"
	}

	// Extract userId from DID
	userID, err := extractUserIDFromDID(key.DID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting userId from DID: %v\n", err)
		os.Exit(1)
	}

	// Step 1: Create signed meta
	fmt.Println("\nCreating metadata...")
	now := time.Now().UTC().Format(time.RFC3339)

	// Convert ACL to []any for consistent canonical JSON
	aclAny := make([]any, len(aclList))
	for i, v := range aclList {
		aclAny[i] = v
	}

	// Build meta object for signing (without sig)
	metaForSig := map[string]any{
		"hash":        hash,
		"owner":       key.DID,
		"acl":         aclAny,
		"contentType": ct,
		"size":        len(data),
		"storage":     storage,
		"created":     now,
	}

	// Sign the meta
	sig, err := signMeta(key.Private, metaForSig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing meta: %v\n", err)
		os.Exit(1)
	}

	// Add signature
	metaForSig["sig"] = sig
	metaBody, _ := json.Marshal(metaForSig)

	resp, err := signedRequest(key, "PUT", *storageURL+"/blob/"+userID+"/"+hash+":meta", metaBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating meta: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error creating meta: %s %s\n", resp.Status, body)
		os.Exit(1)
	}
	fmt.Println("Metadata created ✓")

	// Step 2: Upload blob
	fmt.Println("Uploading blob...")
	resp, err = signedRequest(key, "PUT", *storageURL+"/blob/"+userID+"/"+hash, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error uploading blob: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error uploading blob: %s %s\n", resp.Status, body)
		os.Exit(1)
	}
	fmt.Println("Blob uploaded ✓")
	fmt.Printf("\nURL: %s/blob/%s/%s\n", *storageURL, userID, hash)
}

func cmdDownload(args []string) {
	fs := flag.NewFlagSet("download", flag.ExitOnError)
	keyPath := fs.String("key", "", "Path to private key JSON")
	didOverride := fs.String("did", "", "DID to use (overrides key file)")
	storageURL := fs.String("storage", "https://storage.greything.com", "Storage API URL")
	outPath := fs.String("out", "", "Output file path")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: gt-blob download <hash> --key <path>")
		os.Exit(1)
	}
	hash := fs.Arg(0)

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --key is required")
		os.Exit(1)
	}

	// Load key
	key, err := loadKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}
	if *didOverride != "" {
		key.DID = *didOverride
	}
	if key.DID == "" {
		fmt.Fprintln(os.Stderr, "Error: DID not found in key file, use --did")
		os.Exit(1)
	}

	// Parse hash - could be "userId/hash" or just "hash"
	var userID, actualHash string
	if strings.Contains(hash, "/") {
		parts := strings.SplitN(hash, "/", 2)
		userID = parts[0]
		actualHash = parts[1]
	} else {
		// Use own userId
		var err error
		userID, err = extractUserIDFromDID(key.DID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		actualHash = hash
	}

	// Download
	resp, err := signedRequest(key, "GET", *storageURL+"/blob/"+userID+"/"+actualHash, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error: %s %s\n", resp.Status, body)
		os.Exit(1)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}

	// Verify hash
	computed := computeHash(data)
	if computed != actualHash {
		fmt.Fprintf(os.Stderr, "Warning: hash mismatch! Expected %s, got %s\n", actualHash, computed)
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Downloaded %d bytes to %s\n", len(data), *outPath)
	} else {
		os.Stdout.Write(data)
	}
}

func cmdMeta(args []string) {
	fs := flag.NewFlagSet("meta", flag.ExitOnError)
	keyPath := fs.String("key", "", "Path to private key JSON")
	didOverride := fs.String("did", "", "DID to use (overrides key file)")
	storageURL := fs.String("storage", "https://storage.greything.com", "Storage API URL")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: gt-blob meta <hash> --key <path>")
		os.Exit(1)
	}
	hash := fs.Arg(0)

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --key is required")
		os.Exit(1)
	}

	key, err := loadKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}
	if *didOverride != "" {
		key.DID = *didOverride
	}
	if key.DID == "" {
		fmt.Fprintln(os.Stderr, "Error: DID not found in key file, use --did")
		os.Exit(1)
	}

	// Parse hash - could be "userId/hash" or just "hash"
	var userID, actualHash string
	if strings.Contains(hash, "/") {
		parts := strings.SplitN(hash, "/", 2)
		userID = parts[0]
		actualHash = parts[1]
	} else {
		var err error
		userID, err = extractUserIDFromDID(key.DID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		actualHash = hash
	}

	resp, err := signedRequest(key, "GET", *storageURL+"/blob/"+userID+"/"+actualHash+":meta", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Error: %s %s\n", resp.Status, body)
		os.Exit(1)
	}

	// Pretty print
	var meta map[string]any
	json.Unmarshal(body, &meta)
	pretty, _ := json.MarshalIndent(meta, "", "  ")
	fmt.Println(string(pretty))
}

func cmdDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	keyPath := fs.String("key", "", "Path to private key JSON")
	didOverride := fs.String("did", "", "DID to use (overrides key file)")
	storageURL := fs.String("storage", "https://storage.greything.com", "Storage API URL")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: gt-blob delete <hash> --key <path>")
		os.Exit(1)
	}
	hash := fs.Arg(0)

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --key is required")
		os.Exit(1)
	}

	key, err := loadKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}
	if *didOverride != "" {
		key.DID = *didOverride
	}
	if key.DID == "" {
		fmt.Fprintln(os.Stderr, "Error: DID not found in key file, use --did")
		os.Exit(1)
	}

	// Parse hash - could be "userId/hash" or just "hash"
	var userID, actualHash string
	if strings.Contains(hash, "/") {
		parts := strings.SplitN(hash, "/", 2)
		userID = parts[0]
		actualHash = parts[1]
	} else {
		var err error
		userID, err = extractUserIDFromDID(key.DID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		actualHash = hash
	}

	resp, err := signedRequest(key, "DELETE", *storageURL+"/blob/"+userID+"/"+actualHash, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error: %s %s\n", resp.Status, body)
		os.Exit(1)
	}

	fmt.Println("Deleted ✓")
}

// Key loading and signing

type KeyFile struct {
	KID              string `json:"kid"`
	KTY              string `json:"kty"`
	DID              string `json:"did"`
	PrivateKeyBase58 string `json:"privateKeyBase58"`
	PrivateKeyB64URL string `json:"privateKeyB64Url"`
}

type LoadedKey struct {
	DID     string
	Private ed25519.PrivateKey
}

func loadKey(path string) (*LoadedKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, err
	}

	kty := strings.ToLower(kf.KTY)
	if kty != "ed25519" {
		return nil, fmt.Errorf("unsupported key type: %s", kf.KTY)
	}

	var privBytes []byte

	if kf.PrivateKeyB64URL != "" {
		privBytes, err = crypto.DecodeBase64URL(kf.PrivateKeyB64URL)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key (b64url): %v", err)
		}
	} else if kf.PrivateKeyBase58 != "" {
		privBytes, err = crypto.Base58Decode(kf.PrivateKeyBase58)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key (base58): %v", err)
		}
	} else {
		return nil, fmt.Errorf("no private key found in key file")
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(privBytes))
	}

	return &LoadedKey{
		DID:     kf.DID,
		Private: ed25519.PrivateKey(privBytes),
	}, nil
}

func signedRequest(key *LoadedKey, method, url string, body []byte) (*http.Response, error) {
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Extract path from URL
	path := url
	if idx := strings.Index(url, "://"); idx > 0 {
		rest := url[idx+3:]
		if idx2 := strings.Index(rest, "/"); idx2 > 0 {
			path = rest[idx2:]
		}
	}

	// Build signature payload: timestamp|METHOD|path|body-hash
	// Note: body hash is currently not verified on server side
	bodyHash := ""
	payload := fmt.Sprintf("%s|%s|%s|%s", timestamp, method, path, bodyHash)

	// Sign
	sig := ed25519.Sign(key.Private, []byte(payload))
	sigB64 := crypto.EncodeBase64URL(sig)

	// Create request
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-GT-DID", key.DID)
	req.Header.Set("X-GT-Timestamp", timestamp)
	req.Header.Set("X-GT-Signature", sigB64)

	if body != nil {
		if method == "PUT" && !strings.HasSuffix(path, ":meta") {
			req.Header.Set("Content-Type", "application/octet-stream")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	return http.DefaultClient.Do(req)
}

// Helpers

func computeHash(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256-" + hex.EncodeToString(h[:])
}

func extractUserIDFromDID(did string) (string, error) {
	// Expected format: did:web:did.greything.com:u:{userID}
	parts := strings.Split(did, ":")
	if len(parts) < 5 || parts[0] != "did" || parts[1] != "web" {
		return "", fmt.Errorf("invalid DID format: %s", did)
	}
	return parts[len(parts)-1], nil
}

func signMeta(privKey ed25519.PrivateKey, meta map[string]any) (string, error) {
	// Canonical JSON (sorted keys, no whitespace)
	canonical, err := canonicalJSON(meta)
	if err != nil {
		return "", err
	}

	// Sign
	sig := ed25519.Sign(privKey, canonical)
	return crypto.EncodeBase64URL(sig), nil
}

func canonicalJSON(data map[string]any) ([]byte, error) {
	return crypto.CanonicalJSON(data)
}

func detectContentType(path string, data []byte) string {
	// By extension
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(lower, ".png"):
		return "image/png"
	case strings.HasSuffix(lower, ".gif"):
		return "image/gif"
	case strings.HasSuffix(lower, ".webp"):
		return "image/webp"
	case strings.HasSuffix(lower, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(lower, ".mp4"):
		return "video/mp4"
	case strings.HasSuffix(lower, ".webm"):
		return "video/webm"
	case strings.HasSuffix(lower, ".json"):
		return "application/json"
	case strings.HasSuffix(lower, ".txt"):
		return "text/plain"
	case strings.HasSuffix(lower, ".html"):
		return "text/html"
	case strings.HasSuffix(lower, ".css"):
		return "text/css"
	case strings.HasSuffix(lower, ".js"):
		return "application/javascript"
	}

	// By magic bytes
	if len(data) >= 4 {
		switch {
		case data[0] == 0xFF && data[1] == 0xD8:
			return "image/jpeg"
		case data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G':
			return "image/png"
		case data[0] == 'G' && data[1] == 'I' && data[2] == 'F':
			return "image/gif"
		}
	}

	return "application/octet-stream"
}
