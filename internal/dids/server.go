package dids

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"greything/internal/crypto"
	"greything/internal/did"
)

const maxTimestampAge = 5 * time.Minute

// Server handles DIDS API requests (DID document updates, claims).
type Server struct {
	Domain             string // e.g. "did.greything.com"
	DocRoot            string // e.g. "/var/www/did"
	StorageURL         string // e.g. "https://storage.greything.com"
	StorageInternalURL string // e.g. "http://127.0.0.1:8090" — used for server-side fetches
}

// Handler returns the HTTP handler for the DIDS API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/did/", s.handleDID)
	mux.HandleFunc("/api/v1/external-did/reindex", s.handleExternalReindex)
	mux.HandleFunc("/api/v1/external-did", s.handleExternalDID)
	mux.HandleFunc("/api/v1/search", s.handleSearch)
	mux.HandleFunc("/api/v1/lookup", s.handleLookup)
	return mux
}

// handleDID dispatches to PUT (update DID doc) or POST reindex.
func (s *Server) handleDID(w http.ResponseWriter, r *http.Request) {
	// /api/v1/did/{id}/reindex or /api/v1/did/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/did/")

	if strings.HasSuffix(path, "/reindex") {
		s.handleReindex(w, r)
		return
	}

	if r.Method != http.MethodPut {
		errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use PUT")
		return
	}
	s.handlePutDID(w, r)
}

func (s *Server) handlePutDID(w http.ResponseWriter, r *http.Request) {
	// Extract {id} from /api/v1/did/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/did/")
	if id == "" || strings.Contains(id, "/") {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid DID id in URL")
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "cannot read body")
		return
	}

	// Authenticate — for new DIDs, we pass the body to extract the root key
	auth, err := s.authenticate(r, id, body)
	if err != nil {
		ae, ok := err.(*authError)
		if ok {
			errorJSON(w, ae.statusCode, http.StatusText(ae.statusCode), ae.message)
		} else {
			errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		}
		return
	}

	// Parse new DID document
	var newDoc did.DIDDocument
	if err := json.Unmarshal(body, &newDoc); err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	// Protected field validation: device keys cannot modify root key or recovery policy
	if !auth.isRootKey {
		existingDoc, err := s.loadDIDDoc(id)
		if err == nil && len(existingDoc.VerificationMethod) > 0 {
			if len(newDoc.VerificationMethod) == 0 ||
				newDoc.VerificationMethod[0].PublicKeyMultibase != existingDoc.VerificationMethod[0].PublicKeyMultibase {
				errorJSON(w, http.StatusForbidden, "forbidden", "device keys cannot modify root key")
				return
			}
			if !recoveryPoliciesEqual(existingDoc.RecoveryPolicy, newDoc.RecoveryPolicy) {
				errorJSON(w, http.StatusForbidden, "forbidden", "device keys cannot modify recovery policy")
				return
			}
		}
	}

	expectedDID := fmt.Sprintf("did:web:%s:u:%s", s.Domain, id)

	// Validate: doc.ID must match expected DID
	if newDoc.ID != expectedDID {
		errorJSON(w, http.StatusBadRequest, "bad_request", "document ID does not match URL")
		return
	}

	// Validate: at least one verification method
	if len(newDoc.VerificationMethod) == 0 {
		errorJSON(w, http.StatusBadRequest, "bad_request", "document must have at least one verificationMethod")
		return
	}

	// Validate: first VM must be Ed25519
	if newDoc.VerificationMethod[0].Type != "Ed25519VerificationKey2020" {
		errorJSON(w, http.StatusBadRequest, "bad_request", "first verificationMethod must be Ed25519VerificationKey2020")
		return
	}

	// Write to disk
	dirPath := filepath.Join(s.DocRoot, "u", id)
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal", "cannot create directory")
		return
	}

	filePath := filepath.Join(dirPath, "did.json")
	if err := os.WriteFile(filePath, body, 0o644); err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal", "cannot write file")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// authError distinguishes forbidden (DID mismatch) from unauthorized (bad signature).
type authError struct {
	statusCode int
	message    string
}

func (e *authError) Error() string { return e.message }

// authResult contains the result of authentication.
type authResult struct {
	key       []byte
	isRootKey bool
}

// authenticate verifies the X-GT-DID/Timestamp/Signature headers against any Ed25519 key
// from the existing did.json on disk. For PUT DID (new user creation), if no did.json
// exists yet, it falls back to verifying against the root key from the request body.
// Returns which key matched and whether it was the root key.
func (s *Server) authenticate(r *http.Request, id string, body []byte) (*authResult, error) {
	expectedDID := fmt.Sprintf("did:web:%s:u:%s", s.Domain, id)

	authDID := r.Header.Get("X-GT-DID")
	timestamp := r.Header.Get("X-GT-Timestamp")
	signature := r.Header.Get("X-GT-Signature")

	if authDID == "" || timestamp == "" || signature == "" {
		return nil, &authError{http.StatusUnauthorized, "missing auth headers"}
	}

	if authDID != expectedDID {
		return nil, &authError{http.StatusForbidden, "auth DID does not match URL DID"}
	}

	// Verify timestamp freshness
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, &authError{http.StatusUnauthorized, "invalid timestamp"}
	}
	if math.Abs(time.Since(ts).Seconds()) > maxTimestampAge.Seconds() {
		return nil, &authError{http.StatusUnauthorized, "timestamp too old"}
	}

	// Build signature payload
	h := sha256.Sum256(body)
	bodyHash := "sha256-" + hex.EncodeToString(h[:])
	payload := fmt.Sprintf("%s|%s|%s|%s", timestamp, r.Method, r.URL.Path, bodyHash)

	sigBytes, err := crypto.DecodeBase64URL(signature)
	if err != nil {
		return nil, &authError{http.StatusUnauthorized, "invalid signature encoding"}
	}

	existingDoc, err := s.loadDIDDoc(id)
	if err == nil {
		// Existing document — try all Ed25519 keys
		if len(existingDoc.VerificationMethod) == 0 {
			return nil, &authError{http.StatusInternalServerError, "existing document has no verificationMethod"}
		}
		for i, vm := range existingDoc.VerificationMethod {
			if vm.Type != "Ed25519VerificationKey2020" {
				continue
			}
			pubKey, err := crypto.DecodeMultibase(vm.PublicKeyMultibase)
			if err != nil || len(pubKey) != 32 {
				continue
			}
			if crypto.VerifyEd25519Bytes(pubKey, []byte(payload), sigBytes) {
				return &authResult{key: pubKey, isRootKey: i == 0}, nil
			}
		}
		return nil, &authError{http.StatusUnauthorized, "signature verification failed"}
	}

	// New DID — try to extract root key from body (for PUT DID creation)
	var newDoc did.DIDDocument
	if err := json.Unmarshal(body, &newDoc); err != nil {
		return nil, &authError{http.StatusUnauthorized, "no existing DID and cannot parse body for key"}
	}
	if len(newDoc.VerificationMethod) == 0 {
		return nil, &authError{http.StatusUnauthorized, "no existing DID and no verificationMethod in body"}
	}
	verifyKey, err := crypto.DecodeMultibase(newDoc.VerificationMethod[0].PublicKeyMultibase)
	if err != nil || len(verifyKey) != 32 {
		return nil, &authError{http.StatusUnauthorized, "invalid root key in new document"}
	}

	if !crypto.VerifyEd25519Bytes(verifyKey, []byte(payload), sigBytes) {
		return nil, &authError{http.StatusUnauthorized, "signature verification failed"}
	}

	return &authResult{key: verifyKey, isRootKey: true}, nil
}

// loadDIDDoc loads a DID document from disk. Returns error if not found.
func (s *Server) loadDIDDoc(id string) (*did.DIDDocument, error) {
	filePath := filepath.Join(s.DocRoot, "u", id, "did.json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var doc did.DIDDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func recoveryPoliciesEqual(a, b *did.RecoveryPolicy) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Type == b.Type && a.StorageHead == b.StorageHead && a.SetAt == b.SetAt
}

// handleExternalDID accepts a URL to an external DID document, fetches it,
// validates it, verifies ownership via Ed25519 signature, and stores a reference.
// POST /api/v1/external-did
// Body: {"url": "...", "timestamp": "...", "signature": "...", "keyId": "..."}
// Signature payload: "submit-did|{url}|{timestamp}"
func (s *Server) handleExternalDID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	// Accept two formats:
	// 1. Cloudflare-safe short fields: {h: "host/path", t: "2026-02-26t06:45:00z", s: "sig", k: "keyId"}
	// 2. Full fields: {url: "https://...", timestamp: "...", signature: "...", keyId: "..."}
	var req struct {
		// Short field names (Cloudflare-safe)
		H string `json:"h"`
		T string `json:"t"`
		S string `json:"s"`
		K string `json:"k"`
		// Full field names (direct/curl usage)
		URL       string `json:"url"`
		Timestamp string `json:"timestamp"`
		Signature string `json:"signature"`
		KeyID     string `json:"keyId"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "cannot read body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	// Merge short fields into full fields
	if req.H != "" {
		req.URL = req.H
	}
	if req.T != "" {
		req.Timestamp = req.T
	}
	if req.S != "" {
		req.Signature = req.S
	}
	if req.K != "" {
		req.KeyID = req.K
	}

	if req.URL == "" {
		errorJSON(w, http.StatusBadRequest, "bad_request", "'url' or 'h' field is required")
		return
	}

	// Reconstruct full URL from stripped form
	reqURL := req.URL
	if !strings.HasPrefix(reqURL, "https://") {
		reqURL = "https://" + reqURL
	}
	if !strings.HasSuffix(reqURL, "/did.json") {
		reqURL = reqURL + "/did.json"
	}

	// Require signature fields
	if req.Timestamp == "" || req.Signature == "" {
		errorJSON(w, http.StatusBadRequest, "bad_request", "timestamp and signature are required")
		return
	}

	// Verify timestamp freshness — accept both unix seconds and RFC3339
	var ts time.Time
	if unixSec, err2 := strconv.ParseInt(req.Timestamp, 10, 64); err2 == nil {
		ts = time.Unix(unixSec, 0)
	} else {
		var err3 error
		ts, err3 = time.Parse(time.RFC3339, req.Timestamp)
		if err3 != nil {
			errorJSON(w, http.StatusBadRequest, "bad_request", "invalid timestamp format")
			return
		}
	}
	if math.Abs(time.Since(ts).Seconds()) > 300 { // 5 minutes
		errorJSON(w, http.StatusUnauthorized, "unauthorized", "timestamp too old")
		return
	}


	// Fetch the DID document
	fetchReq, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid URL")
		return
	}
	fetchReq.Header.Set("User-Agent", "GreyThing-DID-Resolver/1.0")
	resp, err := http.DefaultClient.Do(fetchReq)
	if err != nil {
		errorJSON(w, http.StatusBadGateway, "fetch_failed", "cannot fetch DID document: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorJSON(w, http.StatusBadGateway, "fetch_failed", fmt.Sprintf("DID document fetch returned %d", resp.StatusCode))
		return
	}

	docData, err := io.ReadAll(resp.Body)
	if err != nil {
		errorJSON(w, http.StatusBadGateway, "fetch_failed", "cannot read DID document body")
		return
	}

	var doc did.DIDDocument
	if err := json.Unmarshal(docData, &doc); err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid DID document JSON")
		return
	}

	// Validate: must be a did:web DID
	if !strings.HasPrefix(doc.ID, "did:web:") {
		errorJSON(w, http.StatusBadRequest, "bad_request", "DID must be did:web")
		return
	}

	// Validate: must NOT be a local DID (those go through /api/v1/did/{id})
	localPrefix := fmt.Sprintf("did:web:%s:u:", s.Domain)
	if strings.HasPrefix(doc.ID, localPrefix) {
		errorJSON(w, http.StatusBadRequest, "bad_request", "local DIDs should use /api/v1/did/{id} instead")
		return
	}

	// Validate: at least one Ed25519 verification method
	hasEd25519 := false
	for _, vm := range doc.VerificationMethod {
		if vm.Type == "Ed25519VerificationKey2020" {
			hasEd25519 = true
			break
		}
	}
	if !hasEd25519 {
		errorJSON(w, http.StatusBadRequest, "bad_request", "DID document must have at least one Ed25519VerificationKey2020")
		return
	}

	// Verify ownership: signature must match one of the Ed25519 keys in the document
	sigBytes, err := crypto.DecodeBase64URL(req.Signature)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid signature encoding")
		return
	}
	sigPayload := fmt.Sprintf("submit-did|%s|%s", reqURL, req.Timestamp)
	verified := false
	for _, vm := range doc.VerificationMethod {
		if vm.Type != "Ed25519VerificationKey2020" {
			continue
		}
		pubKey, err := crypto.DecodeMultibase(vm.PublicKeyMultibase)
		if err != nil || len(pubKey) != 32 {
			continue
		}
		if crypto.VerifyEd25519Bytes(pubKey, []byte(sigPayload), sigBytes) {
			verified = true
			break
		}
	}
	if !verified {
		errorJSON(w, http.StatusUnauthorized, "unauthorized", "signature verification failed — you must sign with a key from this DID document")
		return
	}

	// Validate: the URL matches what we'd expect from did:web resolution
	expectedURL := didWebToHTTPS(doc.ID)
	if expectedURL != "" && expectedURL != reqURL {
		errorJSON(w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("URL does not match DID: expected %s", expectedURL))
		return
	}

	// Store external DID reference
	// Use a safe directory name derived from the DID
	safeName := strings.ReplaceAll(doc.ID, ":", "-")
	safeName = strings.ReplaceAll(safeName, "/", "-")
	dirPath := filepath.Join(s.DocRoot, "ext", safeName)
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal", "cannot create directory")
		return
	}

	// Save the DID document
	didPath := filepath.Join(dirPath, "did.json")
	if err := os.WriteFile(didPath, docData, 0o644); err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal", "cannot write DID document")
		return
	}

	// Save the source URL for refresh
	refData, _ := json.Marshal(map[string]string{
		"url":       reqURL,
		"did":       doc.ID,
		"fetchedAt": time.Now().UTC().Format(time.RFC3339),
	})
	refPath := filepath.Join(dirPath, "ref.json")
	os.WriteFile(refPath, refData, 0o644)

	// Try to fetch and index claims from the DID's storage endpoint
	s.indexExternalClaims(doc, dirPath)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"did":    doc.ID,
	})
}

// didWebToHTTPS converts a did:web DID to the expected HTTPS URL.
func didWebToHTTPS(didStr string) string {
	if !strings.HasPrefix(didStr, "did:web:") {
		return ""
	}
	parts := strings.Split(didStr[8:], ":")
	if len(parts) == 0 {
		return ""
	}
	domain := parts[0]
	if len(parts) == 1 {
		return "https://" + domain + "/.well-known/did.json"
	}
	path := strings.Join(parts[1:], "/")
	return "https://" + domain + "/" + path + "/did.json"
}

// handleExternalReindex re-indexes claims for an external DID.
// POST /api/v1/external-did/reindex  body: {"did":"did:web:..."}
func (s *Server) handleExternalReindex(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	var req struct {
		DID string `json:"did"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "cannot read body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil || req.DID == "" {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid JSON or missing 'did' field")
		return
	}

	// Must be an external DID (not local)
	localPrefix := fmt.Sprintf("did:web:%s:u:", s.Domain)
	if strings.HasPrefix(req.DID, localPrefix) {
		errorJSON(w, http.StatusBadRequest, "bad_request", "use /api/v1/did/{id}/reindex for local DIDs")
		return
	}

	// Find the stored external DID directory
	safeName := strings.ReplaceAll(req.DID, ":", "-")
	safeName = strings.ReplaceAll(safeName, "/", "-")
	dirPath := filepath.Join(s.DocRoot, "ext", safeName)

	didPath := filepath.Join(dirPath, "did.json")
	docData, err := os.ReadFile(didPath)
	if err != nil {
		errorJSON(w, http.StatusNotFound, "not_found", "external DID not registered — submit it first via /api/v1/external-did")
		return
	}

	var doc did.DIDDocument
	if err := json.Unmarshal(docData, &doc); err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal", "stored DID document is invalid")
		return
	}

	s.indexExternalClaims(doc, dirPath)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "did": req.DID})
}

// indexExternalClaims fetches claims from an external DID's storage endpoint and indexes them.
func (s *Server) indexExternalClaims(doc did.DIDDocument, dirPath string) {
	// Find storage endpoint
	var storageEndpoint string
	for _, svc := range doc.Service {
		if svc.Type == "SolidPod" && svc.ServiceEndpoint != "" {
			storageEndpoint = strings.TrimRight(svc.ServiceEndpoint, "/")
			break
		}
	}
	if storageEndpoint == "" {
		return
	}

	// Try to fetch claims head
	headURL := storageEndpoint + "/heads/claims"
	headResp, err := http.Get(headURL)
	if err != nil || headResp.StatusCode != http.StatusOK {
		if headResp != nil {
			headResp.Body.Close()
		}
		return
	}
	defer headResp.Body.Close()

	var head struct {
		Head string `json:"head"`
	}
	if err := json.NewDecoder(headResp.Body).Decode(&head); err != nil || head.Head == "" {
		return
	}

	// Fetch claims blob
	hexHash := strings.TrimPrefix(head.Head, "sha256-")
	blobURL := storageEndpoint + "/blobs/sha256/" + hexHash
	blobResp, err := http.Get(blobURL)
	if err != nil || blobResp.StatusCode != http.StatusOK {
		if blobResp != nil {
			blobResp.Body.Close()
		}
		return
	}
	defer blobResp.Body.Close()

	blobData, err := io.ReadAll(blobResp.Body)
	if err != nil {
		return
	}

	var manifest ClaimsManifest
	if err := json.Unmarshal(blobData, &manifest); err != nil {
		return
	}

	// Validate manifest DID matches document DID
	if manifest.DID != doc.ID {
		return
	}

	// Write claims index
	index := ClaimsIndex{
		DID:       doc.ID,
		Claims:    manifest.Claims,
		HeadHash:  head.Head,
		IndexedAt: time.Now().UTC().Format(time.RFC3339),
	}
	indexData, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return
	}
	indexPath := filepath.Join(dirPath, "claims-index.json")
	os.WriteFile(indexPath, indexData, 0o644)
}

func errorJSON(w http.ResponseWriter, status int, errCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": errCode, "message": message})
}
