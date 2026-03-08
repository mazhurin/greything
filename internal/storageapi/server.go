package storageapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"greything/internal/crypto"
	"greything/internal/storage"
)

const (
	MaxHotBlobSize  = 5 * 1024 * 1024   // 5 MB
	MaxColdBlobSize = 500 * 1024 * 1024 // 500 MB
	MaxTimestampAge = 5 * time.Minute

	HotQuotaBytes  = 1 * 1024 * 1024 * 1024  // 1 GB
	ColdQuotaBytes = 10 * 1024 * 1024 * 1024 // 10 GB
)

// Server handles storage API requests.
type Server struct {
	Hot  storage.StorageAdapter
	Cold storage.StorageAdapter

	// DIDResolver resolves DIDs to public keys.
	// For now, we'll use a simple HTTP client to did.greything.com
	DIDBaseURL string
}

// NewServer creates a new storage API server.
func NewServer(hot, cold storage.StorageAdapter, didBaseURL string) *Server {
	return &Server{
		Hot:        hot,
		Cold:       cold,
		DIDBaseURL: strings.TrimRight(didBaseURL, "/"),
	}
}

// Handler returns the HTTP handler for the storage API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// PUT /blob/{hash}:meta - create metadata
	// PUT /blob/{hash} - upload blob
	// GET /blob/{hash}:meta - get metadata
	// GET /blob/{hash} - get blob
	// GET /blob/{hash}:playback - get video playback URL
	// PATCH /blob/{hash}:meta - update ACL
	// DELETE /blob/{hash} - delete blob
	// HEAD /blob/{hash} - check existence

	mux.HandleFunc("/blob/", s.handleBlob)
	mux.HandleFunc("/health", s.handleHealth)

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request) {
	// Parse path: /blob/{userId}/{hash} or /blob/{userId}/{hash}:meta or /blob/{userId}/{hash}:playback
	path := strings.TrimPrefix(r.URL.Path, "/blob/")
	if path == "" {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "missing path")
		return
	}

	// Split into userId and hash
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "path must be /{userId}/{hash}")
		return
	}
	ownerUserID := parts[0]
	hashPart := parts[1]

	var hash, suffix string
	if idx := strings.LastIndex(hashPart, ":"); idx > 0 {
		hash = hashPart[:idx]
		suffix = hashPart[idx+1:]
	} else {
		hash = hashPart
	}

	// Validate hash format
	if !isValidHash(hash) {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "invalid hash format")
		return
	}

	// Validate userId format (alphanumeric)
	if ownerUserID == "" || !isValidUserID(ownerUserID) {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "invalid userId format")
		return
	}

	switch r.Method {
	case http.MethodPut:
		if suffix == "meta" {
			s.handlePutMeta(w, r, ownerUserID, hash)
		} else if suffix == "" {
			s.handlePutBlob(w, r, ownerUserID, hash)
		} else {
			s.errorResponse(w, http.StatusBadRequest, "bad_request", "invalid path")
		}

	case http.MethodGet:
		if suffix == "meta" {
			s.handleGetMeta(w, r, ownerUserID, hash)
		} else if suffix == "playback" {
			s.handleGetPlayback(w, r, ownerUserID, hash)
		} else if suffix == "" {
			s.handleGetBlob(w, r, ownerUserID, hash)
		} else {
			s.errorResponse(w, http.StatusBadRequest, "bad_request", "invalid path")
		}

	case http.MethodPatch:
		if suffix == "meta" {
			s.handlePatchMeta(w, r, ownerUserID, hash)
		} else {
			s.errorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		}

	case http.MethodDelete:
		if suffix == "" {
			s.handleDeleteBlob(w, r, ownerUserID, hash)
		} else {
			s.errorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		}

	case http.MethodHead:
		if suffix == "" {
			s.handleHeadBlob(w, r, ownerUserID, hash)
		} else {
			s.errorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		}

	default:
		s.errorResponse(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
	}
}

// handlePutMeta creates metadata for a new blob.
func (s *Server) handlePutMeta(w http.ResponseWriter, r *http.Request, ownerUserID, hash string) {
	// Authenticate
	auth, err := s.authenticate(r)
	if err != nil {
		s.errorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Verify that authenticated user matches the path owner
	if auth.UserID != ownerUserID {
		s.errorResponse(w, http.StatusForbidden, "forbidden", "can only create blobs in your own namespace")
		return
	}

	// Parse request body as signed meta
	var meta storage.Meta
	if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	// Validate required fields
	if meta.Hash == "" {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "hash required")
		return
	}
	if meta.Hash != hash {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "hash in body doesn't match URL")
		return
	}
	if meta.Owner == "" {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "owner required")
		return
	}
	if meta.Owner != auth.DID {
		s.errorResponse(w, http.StatusForbidden, "forbidden", "owner must match authenticated DID")
		return
	}
	if meta.ContentType == "" {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "contentType required")
		return
	}
	if meta.Size <= 0 {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "size must be positive")
		return
	}
	if meta.Storage != "hot" && meta.Storage != "cold" {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "storage must be 'hot' or 'cold'")
		return
	}
	if meta.Sig == "" {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "sig required")
		return
	}

	// Verify signature
	if err := s.verifyMetaSignature(&meta, auth.DID); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "invalid signature: "+err.Error())
		return
	}

	// Check size limits
	if meta.Storage == "hot" && meta.Size > MaxHotBlobSize {
		s.errorResponse(w, http.StatusRequestEntityTooLarge, "too_large", "max hot blob size is 5MB")
		return
	}
	if meta.Storage == "cold" && meta.Size > MaxColdBlobSize {
		s.errorResponse(w, http.StatusRequestEntityTooLarge, "too_large", "max cold blob size is 500MB")
		return
	}

	// Get storage adapter
	adapter := s.getAdapter(meta.Storage)

	// Check if meta already exists
	metaKey := ownerUserID + "/" + hash + ".meta"
	exists, err := adapter.Exists(metaKey)
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if exists {
		s.errorResponse(w, http.StatusConflict, "conflict", "meta already exists")
		return
	}

	// Check quota
	quotaLimit := HotQuotaBytes
	if meta.Storage == "cold" {
		quotaLimit = ColdQuotaBytes
	}
	currentSize, err := adapter.Size(ownerUserID + "/")
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if currentSize+meta.Size > int64(quotaLimit) {
		s.errorResponse(w, http.StatusInsufficientStorage, "quota_exceeded", "storage quota exceeded")
		return
	}

	// Store meta as-is (already signed by client)
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	if err := adapter.Put(metaKey, metaBytes); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	// Response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"hash":    hash,
		"owner":   meta.Owner,
		"created": meta.Created,
	})
}

// handlePutBlob uploads blob bytes.
func (s *Server) handlePutBlob(w http.ResponseWriter, r *http.Request, ownerUserID, hash string) {
	// Authenticate
	auth, err := s.authenticate(r)
	if err != nil {
		s.errorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Verify that authenticated user matches the path owner
	if auth.UserID != ownerUserID {
		s.errorResponse(w, http.StatusForbidden, "forbidden", "can only upload to your own namespace")
		return
	}

	// Try hot storage first, then cold
	meta, adapter, err := s.findMeta(ownerUserID, hash)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, "not_found", "meta not found, create meta first")
		return
	}

	// Verify owner
	if meta.Owner != auth.DID {
		s.errorResponse(w, http.StatusForbidden, "forbidden", "not owner")
		return
	}

	// Check if blob already exists
	blobKey := ownerUserID + "/" + hash
	exists, err := adapter.Exists(blobKey)
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if exists {
		s.errorResponse(w, http.StatusConflict, "conflict", "blob already exists")
		return
	}

	// Read body with size limit
	maxSize := MaxHotBlobSize
	if meta.Storage == "cold" {
		maxSize = MaxColdBlobSize
	}
	limitedReader := io.LimitReader(r.Body, int64(maxSize)+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "failed to read body")
		return
	}
	if len(data) > maxSize {
		s.errorResponse(w, http.StatusRequestEntityTooLarge, "too_large", "blob too large")
		return
	}

	// Verify size matches meta
	if int64(len(data)) != meta.Size {
		s.errorResponse(w, http.StatusUnprocessableEntity, "unprocessable",
			fmt.Sprintf("size mismatch: expected %d, got %d", meta.Size, len(data)))
		return
	}

	// Verify hash
	computed := computeHash(data)
	if computed != hash {
		s.errorResponse(w, http.StatusUnprocessableEntity, "unprocessable", "hash mismatch")
		return
	}

	// Store blob
	if err := adapter.Put(blobKey, data); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// handleGetBlob retrieves blob bytes.
func (s *Server) handleGetBlob(w http.ResponseWriter, r *http.Request, ownerUserID, hash string) {
	// Find the blob metadata in owner's storage
	meta, adapter, err := s.findMeta(ownerUserID, hash)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}

	// Check if blob is public
	isPublic := false
	for _, acl := range meta.ACL {
		if acl == "*" {
			isPublic = true
			break
		}
	}

	if isPublic {
		// Public blob - no auth required
	} else {
		// Private blob - require auth and ACL check
		auth, err := s.authenticate(r)
		if err != nil {
			s.errorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		if !s.checkACL(meta, auth.DID) {
			// Return 404 to not reveal blob existence
			s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
			return
		}
	}

	blobKey := ownerUserID + "/" + hash
	data, err := adapter.Get(blobKey)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}

	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)
}

// handleGetMeta retrieves blob metadata.
func (s *Server) handleGetMeta(w http.ResponseWriter, r *http.Request, ownerUserID, hash string) {
	meta, _, err := s.findMeta(ownerUserID, hash)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}

	// Check if blob is public
	isPublic := false
	for _, acl := range meta.ACL {
		if acl == "*" {
			isPublic = true
			break
		}
	}

	if !isPublic {
		// Private blob - require auth and ACL check
		auth, err := s.authenticate(r)
		if err != nil {
			s.errorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		if !s.checkACL(meta, auth.DID) {
			s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

// handlePatchMeta updates blob metadata (ACL only).
func (s *Server) handlePatchMeta(w http.ResponseWriter, r *http.Request, ownerUserID, hash string) {
	auth, err := s.authenticate(r)
	if err != nil {
		s.errorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Verify that authenticated user matches the path owner
	if auth.UserID != ownerUserID {
		s.errorResponse(w, http.StatusForbidden, "forbidden", "can only modify your own blobs")
		return
	}

	meta, adapter, err := s.findMeta(ownerUserID, hash)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}

	// Only owner can update
	if meta.Owner != auth.DID {
		s.errorResponse(w, http.StatusForbidden, "forbidden", "not owner")
		return
	}

	// Parse update request
	var update struct {
		ACL []string `json:"acl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		s.errorResponse(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	// Update meta
	meta.ACL = update.ACL
	meta.Updated = time.Now().UTC().Format(time.RFC3339)

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	metaKey := ownerUserID + "/" + hash + ".meta"
	if err := adapter.Put(metaKey, metaBytes); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

// handleDeleteBlob deletes a blob and its metadata.
func (s *Server) handleDeleteBlob(w http.ResponseWriter, r *http.Request, ownerUserID, hash string) {
	auth, err := s.authenticate(r)
	if err != nil {
		s.errorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Verify that authenticated user matches the path owner
	if auth.UserID != ownerUserID {
		s.errorResponse(w, http.StatusForbidden, "forbidden", "can only delete your own blobs")
		return
	}

	meta, adapter, err := s.findMeta(ownerUserID, hash)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}

	// Only owner can delete
	if meta.Owner != auth.DID {
		s.errorResponse(w, http.StatusForbidden, "forbidden", "not owner")
		return
	}

	blobKey := ownerUserID + "/" + hash
	metaKey := ownerUserID + "/" + hash + ".meta"

	// Delete blob (may not exist yet)
	adapter.Delete(blobKey)

	// Delete meta
	if err := adapter.Delete(metaKey); err != nil {
		s.errorResponse(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleHeadBlob checks if a blob exists.
func (s *Server) handleHeadBlob(w http.ResponseWriter, r *http.Request, ownerUserID, hash string) {
	meta, adapter, err := s.findMeta(ownerUserID, hash)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Check if blob is public
	isPublic := false
	for _, acl := range meta.ACL {
		if acl == "*" {
			isPublic = true
			break
		}
	}

	if !isPublic {
		// Private blob - require auth and ACL check
		auth, err := s.authenticate(r)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if !s.checkACL(meta, auth.DID) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}

	// Check if blob data exists
	blobKey := ownerUserID + "/" + hash
	exists, _ := adapter.Exists(blobKey)
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("X-GT-Size", fmt.Sprintf("%d", meta.Size))
	w.Header().Set("X-GT-ContentType", meta.ContentType)
	w.WriteHeader(http.StatusOK)
}

// handleGetPlayback returns a signed URL for video playback.
func (s *Server) handleGetPlayback(w http.ResponseWriter, r *http.Request, ownerUserID, hash string) {
	meta, _, err := s.findMeta(ownerUserID, hash)
	if err != nil {
		s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}

	// Check if blob is public
	isPublic := false
	for _, acl := range meta.ACL {
		if acl == "*" {
			isPublic = true
			break
		}
	}

	if !isPublic {
		// Private blob - require auth and ACL check
		auth, err := s.authenticate(r)
		if err != nil {
			s.errorResponse(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}

		if !s.checkACL(meta, auth.DID) {
			s.errorResponse(w, http.StatusNotFound, "not_found", "blob not found")
			return
		}
	}

	if meta.Delivery == nil || meta.Delivery.Status != "ready" {
		s.errorResponse(w, http.StatusNotFound, "not_found", "video not ready")
		return
	}

	// TODO: Generate signed URL from Cloudflare Stream
	// For now, return placeholder
	expires := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"url":     fmt.Sprintf("https://placeholder.cloudflarestream.com/%s/manifest.m3u8", meta.Delivery.VideoID),
		"expires": expires,
	})
}

// Auth contains authenticated request info.
type Auth struct {
	DID    string
	UserID string
}

// authenticateWithBody verifies the request signature and returns auth info.
// It reads the request body, hashes it for signature verification, and returns the body bytes.
func (s *Server) authenticateWithBody(r *http.Request) (*Auth, []byte, error) {
	did := r.Header.Get("X-GT-DID")
	timestamp := r.Header.Get("X-GT-Timestamp")
	signature := r.Header.Get("X-GT-Signature")

	if did == "" || timestamp == "" || signature == "" {
		return nil, nil, fmt.Errorf("missing auth headers")
	}

	// Parse timestamp
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid timestamp format")
	}

	// Check timestamp freshness
	if time.Since(ts) > MaxTimestampAge {
		return nil, nil, fmt.Errorf("timestamp too old")
	}
	if ts.After(time.Now().Add(time.Minute)) {
		return nil, nil, fmt.Errorf("timestamp in future")
	}

	// Extract user ID from DID
	userID, err := extractUserID(did)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid DID format")
	}

	// Resolve DID to get public key
	pubKey, err := s.resolveDIDKey(did)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve DID: %v", err)
	}

	// Read body and compute hash
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read body")
		}
	}
	h := sha256.Sum256(bodyBytes)
	bodyHash := "sha256-" + hex.EncodeToString(h[:])

	// Build signature payload
	// Format: timestamp|METHOD|path|body-hash
	payload := fmt.Sprintf("%s|%s|%s|%s", timestamp, r.Method, r.URL.Path, bodyHash)

	// Verify signature
	sigBytes, err := crypto.DecodeBase64URL(signature)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature encoding")
	}

	if !crypto.VerifyEd25519Bytes(pubKey, []byte(payload), sigBytes) {
		return nil, nil, fmt.Errorf("invalid signature")
	}

	return &Auth{DID: did, UserID: userID}, bodyBytes, nil
}

// authenticate verifies the request signature (no body). Use authenticateWithBody for PUT/POST.
func (s *Server) authenticate(r *http.Request) (*Auth, error) {
	auth, _, err := s.authenticateWithBody(r)
	return auth, err
}

// resolveDIDKey fetches the public key for a DID.
func (s *Server) resolveDIDKey(did string) ([]byte, error) {
	// Extract user ID and build DID document URL
	userID, err := extractUserID(did)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/u/%s/did.json", s.DIDBaseURL, userID)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DID not found")
	}

	var doc struct {
		VerificationMethod []struct {
			ID                 string `json:"id"`
			Type               string `json:"type"`
			PublicKeyMultibase string `json:"publicKeyMultibase"`
		} `json:"verificationMethod"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	// Find first Ed25519 key
	for _, vm := range doc.VerificationMethod {
		if vm.Type == "Ed25519VerificationKey2020" && vm.PublicKeyMultibase != "" {
			return crypto.DecodeMultibase(vm.PublicKeyMultibase)
		}
	}

	return nil, fmt.Errorf("no Ed25519 key found")
}

// findMeta looks for metadata in hot then cold storage.
func (s *Server) findMeta(userID, hash string) (*storage.Meta, storage.StorageAdapter, error) {
	metaKey := userID + "/" + hash + ".meta"

	// Try hot first
	data, err := s.Hot.Get(metaKey)
	if err == nil {
		var meta storage.Meta
		if err := json.Unmarshal(data, &meta); err != nil {
			return nil, nil, err
		}
		return &meta, s.Hot, nil
	}

	// Try cold
	data, err = s.Cold.Get(metaKey)
	if err == nil {
		var meta storage.Meta
		if err := json.Unmarshal(data, &meta); err != nil {
			return nil, nil, err
		}
		return &meta, s.Cold, nil
	}

	return nil, nil, storage.ErrNotFound
}

// getAdapter returns the storage adapter for the given storage type.
func (s *Server) getAdapter(storageType string) storage.StorageAdapter {
	if storageType == "cold" {
		return s.Cold
	}
	return s.Hot
}

// checkACL verifies if the given DID has access to the blob.
func (s *Server) checkACL(meta *storage.Meta, did string) bool {
	// Owner always has access
	if meta.Owner == did {
		return true
	}

	// Check ACL
	for _, allowed := range meta.ACL {
		if allowed == "*" || allowed == did {
			return true
		}
	}

	return false
}

// errorResponse sends a JSON error response.
func (s *Server) errorResponse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

// Helper functions

func isValidHash(hash string) bool {
	if !strings.HasPrefix(hash, "sha256-") {
		return false
	}
	hexPart := strings.TrimPrefix(hash, "sha256-")
	if len(hexPart) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

func computeHash(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256-" + hex.EncodeToString(h[:])
}

func extractUserID(did string) (string, error) {
	// Expected format: did:web:did.greything.com:u:{userID}
	parts := strings.Split(did, ":")
	if len(parts) < 5 || parts[0] != "did" || parts[1] != "web" {
		return "", fmt.Errorf("invalid DID format")
	}
	// Last part is user ID
	return parts[len(parts)-1], nil
}

func isValidUserID(userID string) bool {
	if len(userID) == 0 || len(userID) > 64 {
		return false
	}
	for _, c := range userID {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// verifyMetaSignature verifies the Ed25519 signature on meta.
func (s *Server) verifyMetaSignature(meta *storage.Meta, ownerDID string) error {
	// Get public key for owner
	pubKey, err := s.resolveDIDKey(ownerDID)
	if err != nil {
		return fmt.Errorf("failed to resolve owner key: %v", err)
	}

	// Build canonical JSON without sig
	// Convert ACL to []any for canonical JSON
	aclAny := make([]any, len(meta.ACL))
	for i, v := range meta.ACL {
		aclAny[i] = v
	}

	metaMap := map[string]any{
		"hash":        meta.Hash,
		"owner":       meta.Owner,
		"acl":         aclAny,
		"contentType": meta.ContentType,
		"size":        meta.Size,
		"storage":     meta.Storage,
		"created":     meta.Created,
	}
	if meta.Duration > 0 {
		metaMap["duration"] = meta.Duration
	}

	canonical, err := crypto.CanonicalJSON(metaMap)
	if err != nil {
		return fmt.Errorf("failed to canonicalize: %v", err)
	}

	// Decode signature
	sigBytes, err := crypto.DecodeBase64URL(meta.Sig)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %v", err)
	}

	// Verify
	if !crypto.VerifyEd25519Bytes(pubKey, canonical, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
