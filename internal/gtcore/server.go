package gtcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"greything/internal/storage"
)

// Server handles GT Core storage API requests.
type Server struct {
	store           storage.StorageAdapter
	heads           *HeadStore
	resolver        DIDResolver
	DIDSInternalURL string // e.g. "http://127.0.0.1:8080" — for proxying reindex
}

// NewServer creates a new GT Core server.
func NewServer(store storage.StorageAdapter, resolver DIDResolver) *Server {
	return &Server{
		store:    store,
		heads:    NewHeadStore(store),
		resolver: resolver,
	}
}

// Handler returns the HTTP handler for the GT Core API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/gt/v1/health", s.handleHealth)
	mux.HandleFunc("/gt/v1/", s.handleRoute)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// parsedRoute holds the parsed components of a GT Core API path.
type parsedRoute struct {
	did      string // e.g. "did:web:did.greything.com:u:anton"
	resource string // "blobs", "heads", "inbox", or "grants"
	// For blobs: algo="sha256", hash=hex
	algo   string
	hash   string
	isMeta bool // true if path ends with :meta
	// For heads: name
	name string
	// For inbox: item ID (empty for list/post)
	inboxItemID string
	// For grants: hash (empty for list/post)
	grantHash string
}

var hexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// parseRoute parses /gt/v1/{did}/blobs/sha256/{hex} or /gt/v1/{did}/heads/{name}
func parseRoute(path string) (*parsedRoute, error) {
	path = strings.TrimPrefix(path, "/gt/v1/")
	if path == "" {
		return nil, errors.New("empty path")
	}

	// Find first known segment: "blobs", "heads", "inbox", or "grants"
	var didPart, rest string
	for _, seg := range []string{"/blobs/", "/heads/", "/inbox", "/grants"} {
		idx := strings.Index(path, seg)
		if idx >= 0 {
			didPart = path[:idx]
			rest = path[idx+len(seg):]
			route := &parsedRoute{did: didPart}
			if seg == "/blobs/" {
				route.resource = "blobs"
				// Expect: sha256/{hex} or sha256/{hex}:meta
				parts := strings.SplitN(rest, "/", 2)
				if len(parts) != 2 || parts[0] != "sha256" {
					return nil, errors.New("invalid blob path: expected sha256/{hex}")
				}
				hashPart := parts[1]
				if strings.HasSuffix(hashPart, ":meta") {
					route.isMeta = true
					hashPart = strings.TrimSuffix(hashPart, ":meta")
				}
				if !hexPattern.MatchString(hashPart) {
					return nil, errors.New("invalid blob hash: expected 64 hex chars")
				}
				route.algo = "sha256"
				route.hash = hashPart
			} else if seg == "/heads/" {
				route.resource = "heads"
				if rest == "" {
					return nil, errors.New("missing head name")
				}
				route.name = rest
			} else if seg == "/grants" {
				route.resource = "grants"
				rest = strings.TrimPrefix(rest, "/")
				if rest != "" {
					if !hexPattern.MatchString(rest) {
						return nil, errors.New("invalid grant hash: expected 64 hex chars")
					}
					route.grantHash = rest
				}
			} else {
				// inbox: rest is "" or "/{id}"
				route.resource = "inbox"
				rest = strings.TrimPrefix(rest, "/")
				if rest != "" {
					if err := validateInboxItemID(rest); err != nil {
						return nil, err
					}
					route.inboxItemID = sanitizeInboxItemID(rest)
				}
			}
			return route, nil
		}
	}

	return nil, errors.New("unknown resource type")
}

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request) {
	// Proxy reindex: /gt/v1/{did}/reindex → gt-dids /api/v1/did/{id}/reindex
	path := strings.TrimPrefix(r.URL.Path, "/gt/v1/")
	if strings.HasSuffix(path, "/reindex") {
		s.handleReindexProxy(w, r, strings.TrimSuffix(path, "/reindex"))
		return
	}

	route, err := parseRoute(r.URL.Path)
	if err != nil {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	switch route.resource {
	case "blobs":
		s.handleBlob(w, r, route)
	case "heads":
		s.handleHead(w, r, route)
	case "inbox":
		s.handleInbox(w, r, route)
	case "grants":
		s.handleGrant(w, r, route)
	default:
		s.errorJSON(w, http.StatusNotFound, "not_found", "unknown resource")
	}
}

// --- Blob handlers ---

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	if route.isMeta {
		switch r.Method {
		case http.MethodGet:
			s.handleBlobMetaGet(w, r, route)
		case http.MethodPut:
			s.handleBlobMetaPut(w, r, route)
		default:
			s.errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or PUT")
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleBlobGet(w, r, route)
	case http.MethodPut:
		s.handleBlobPut(w, r, route)
	case http.MethodDelete:
		s.handleBlobDelete(w, r, route)
	default:
		s.errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET, PUT, or DELETE")
	}
}

func (s *Server) handleBlobGet(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	key := blobKey(route.did, route.hash)
	data, err := s.store.Get(key)
	if errors.Is(err, storage.ErrNotFound) {
		s.errorJSON(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// Check ACL if meta exists
	meta, err := s.loadBlobMeta(route.did, route.hash)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if meta != nil && !isPublicACL(meta.ACL) {
		auth, err := TryAuthenticate(r, s.resolver, nil)
		callerDID := ""
		if err == nil && auth != nil {
			callerDID = auth.DID
		}
		if !checkACL(meta, route.did, callerDID) {
			// ACL denied — check for grant-based access
			// For grant checks, use X-GT-DID header as claimed caller identity.
			// The grant itself is signed by the issuer (blob owner), so if the
			// grant's subject matches the claimed DID, access is authorized
			// by the issuer's signature rather than by verifying the caller's key.
			grantCallerDID := callerDID
			if grantCallerDID == "" {
				grantCallerDID = r.Header.Get("X-GT-DID")
			}
			if grantCallerDID != "" {
				if s.checkGrantAccess(r, route, grantCallerDID) {
					goto serve
				}
			}
			s.errorJSON(w, http.StatusNotFound, "not_found", "blob not found")
			return
		}
	}

serve:

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(data)
}

func (s *Server) handleBlobPut(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	auth, body, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Verify ownership: auth DID must match URL DID
	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	// Verify hash matches body
	h := sha256.Sum256(body)
	actualHex := hex.EncodeToString(h[:])
	if actualHex != route.hash {
		s.errorJSON(w, http.StatusUnprocessableEntity, "hash_mismatch", "body hash does not match URL hash")
		return
	}

	key := blobKey(route.did, route.hash)

	// Check if already exists
	exists, err := s.store.Exists(key)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if exists {
		s.errorJSON(w, http.StatusConflict, "already_exists", "blob already exists")
		return
	}

	if err := s.store.Put(key, body); err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleBlobDelete(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	// Read body for auth (even though DELETE has no meaningful body)
	auth, _, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	key := blobKey(route.did, route.hash)
	err = s.store.Delete(key)
	if errors.Is(err, storage.ErrNotFound) {
		s.errorJSON(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// Clean up meta if it exists
	mk := metaKey(route.did, route.hash)
	_ = s.store.Delete(mk) // ignore ErrNotFound

	w.WriteHeader(http.StatusNoContent)
}

func blobKey(did, hash string) string {
	return did + "/blobs/sha256/" + hash
}

func metaKey(did, hash string) string {
	return blobKey(did, hash) + ":meta"
}

// loadBlobMeta loads meta for a blob. Returns (nil, nil) if no meta exists.
func (s *Server) loadBlobMeta(did, hash string) (*BlobMeta, error) {
	mk := metaKey(did, hash)
	data, err := s.store.Get(mk)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var meta BlobMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func isPublicACL(acl []string) bool {
	for _, entry := range acl {
		if entry == "*" {
			return true
		}
	}
	return false
}

func checkACL(meta *BlobMeta, ownerDID string, callerDID string) bool {
	if callerDID == ownerDID {
		return true
	}
	for _, entry := range meta.ACL {
		if entry == "*" || entry == callerDID {
			return true
		}
	}
	return false
}

// --- Blob meta handlers ---

func (s *Server) handleBlobMetaGet(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	auth, _, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	meta, err := s.loadBlobMeta(route.did, route.hash)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if meta == nil {
		s.errorJSON(w, http.StatusNotFound, "not_found", "meta not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

func (s *Server) handleBlobMetaPut(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	auth, body, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	// Blob must exist
	bk := blobKey(route.did, route.hash)
	exists, err := s.store.Exists(bk)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if !exists {
		s.errorJSON(w, http.StatusNotFound, "not_found", "blob not found")
		return
	}

	var meta BlobMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Check if meta already exists (update vs create)
	existing, err := s.loadBlobMeta(route.did, route.hash)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if existing != nil {
		meta.CreatedAt = existing.CreatedAt
		meta.UpdatedAt = now
	} else {
		meta.CreatedAt = now
	}

	data, err := json.Marshal(meta)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	mk := metaKey(route.did, route.hash)
	if err := s.store.Put(mk, data); err != nil {
		// If already exists, delete and re-put (update)
		if errors.Is(err, storage.ErrAlreadyExists) {
			_ = s.store.Delete(mk)
			if err := s.store.Put(mk, data); err != nil {
				s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
				return
			}
		} else {
			s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

// --- Head handlers ---

func (s *Server) handleHead(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	switch r.Method {
	case http.MethodGet:
		s.handleHeadGet(w, r, route)
	case http.MethodPut:
		s.handleHeadPut(w, r, route)
	default:
		s.errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or PUT")
	}
}

func (s *Server) handleHeadGet(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	head, err := s.heads.GetHead(route.did, route.name)
	if errors.Is(err, storage.ErrNotFound) {
		s.errorJSON(w, http.StatusNotFound, "not_found", "head not found")
		return
	}
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(head)
}

func (s *Server) handleHeadPut(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	auth, body, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	var req HeadUpdateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if req.Head == "" {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "head value is required")
		return
	}

	head, err := s.heads.UpdateHead(route.did, route.name, req)
	if errors.Is(err, ErrConflict) {
		s.errorJSON(w, http.StatusConflict, "conflict", "CAS conflict: expected value does not match current")
		return
	}
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// Auto-reindex when claims head is updated
	if route.name == "claims" && s.DIDSInternalURL != "" {
		go s.triggerReindex(route.did)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(head)
}

// triggerReindex calls gt-dids to reindex claims for a DID (fire-and-forget).
func (s *Server) triggerReindex(didStr string) {
	parts := strings.Split(didStr, ":")
	if len(parts) < 5 || parts[3] != "u" {
		return
	}
	userID := parts[4]

	targetURL := strings.TrimRight(s.DIDSInternalURL, "/") + "/api/v1/did/" + userID + "/reindex"
	req, _ := http.NewRequest(http.MethodPost, targetURL, nil)
	req.Header.Set("X-GT-Internal", "true")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("auto-reindex %s: %v", didStr, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("auto-reindex %s: status %d", didStr, resp.StatusCode)
	}
}

// --- Reindex proxy ---

// handleReindexProxy forwards reindex requests to gt-dids via internal URL.
// Path: /gt/v1/{did}/reindex → POST /api/v1/did/{userID}/reindex on gt-dids.
func (s *Server) handleReindexProxy(w http.ResponseWriter, r *http.Request, didStr string) {
	if r.Method != http.MethodPost {
		s.errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	if s.DIDSInternalURL == "" {
		s.errorJSON(w, http.StatusNotImplemented, "not_configured", "DIDS internal URL not configured")
		return
	}

	// No auth check here — the caller already proved ownership via authenticated
	// putHead on the claims head. We just proxy to gt-dids as an internal request.

	// Extract user ID: did:web:did.greything.com:u:abc123 → abc123
	parts := strings.Split(didStr, ":")
	if len(parts) < 5 || parts[3] != "u" {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "cannot extract user ID from DID")
		return
	}
	userID := parts[4]

	targetPath := "/api/v1/did/" + userID + "/reindex"
	targetURL := strings.TrimRight(s.DIDSInternalURL, "/") + targetPath

	// Forward as internal trusted request (gt-dids skips auth for X-GT-Internal)
	proxyReq, _ := http.NewRequest(http.MethodPost, targetURL, r.Body)
	proxyReq.Header.Set("X-GT-Internal", "true")

	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		log.Printf("reindex proxy error: %v", err)
		s.errorJSON(w, http.StatusBadGateway, "bad_gateway", "cannot reach DIDS server")
		return
	}
	defer resp.Body.Close()

	// Copy response back
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// --- Grant handlers ---

func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	if route.grantHash == "" {
		// /gt/v1/{did}/grants
		switch r.Method {
		case http.MethodPost:
			s.handleGrantPost(w, r, route)
		default:
			s.errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		}
	} else {
		// /gt/v1/{did}/grants/{hash}
		switch r.Method {
		case http.MethodGet:
			s.handleGrantGet(w, r, route)
		default:
			s.errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		}
	}
}

func (s *Server) handleGrantPost(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	auth, body, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}

	// Request auth: caller must own this namespace
	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	var g Grant
	if err := json.Unmarshal(body, &g); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	// Grant issuer must match the route DID (don't trust body issuer)
	if g.Issuer != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "grant issuer must match namespace")
		return
	}

	// Verify grant signature
	if err := VerifyGrant(g, s.resolver); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "grant verification failed: "+err.Error())
		return
	}

	// Compute hash and store
	grantHash, err := ComputeGrantHash(g)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	key := grantKey(route.did, grantHash)
	if err := s.store.Put(key, body); err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"grantHash": grantHash})
}

func (s *Server) handleGrantGet(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	// Grants are public (self-authenticating via signature)
	key := grantKey(route.did, "sha256-"+route.grantHash)
	data, err := s.store.Get(key)
	if err != nil {
		if isNotFoundErr(err) {
			s.errorJSON(w, http.StatusNotFound, "not_found", "grant not found")
			return
		}
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// checkGrantAccess checks if the X-GT-Grant header contains a valid grant
// that authorizes the caller to read the blob.
func (s *Server) checkGrantAccess(r *http.Request, route *parsedRoute, callerDID string) bool {
	grantHashHeader := r.Header.Get("X-GT-Grant")
	if grantHashHeader == "" {
		return false
	}

	// Load grant from storage
	key := grantKey(route.did, grantHashHeader)
	data, err := s.store.Get(key)
	if err != nil {
		log.Printf("[grant] failed to load grant %s: %v", grantHashHeader, err)
		return false
	}

	var g Grant
	if err := json.Unmarshal(data, &g); err != nil {
		log.Printf("[grant] failed to parse grant: %v", err)
		return false
	}

	// Verify grant signature
	if err := VerifyGrant(g, s.resolver); err != nil {
		log.Printf("[grant] signature verification failed: %v", err)
		return false
	}

	// Validate grant for this specific blob read
	blobHash := "sha256-" + route.hash
	if err := ValidateGrantForBlobRead(g, callerDID, route.did, blobHash, time.Now().UTC()); err != nil {
		log.Printf("[grant] validation failed: %v", err)
		return false
	}

	// Critical: grant issuer must be the blob owner
	if g.Issuer != route.did {
		log.Printf("[grant] issuer %s != blob owner %s", g.Issuer, route.did)
		return false
	}

	return true
}

// --- Helpers ---

func (s *Server) errorJSON(w http.ResponseWriter, status int, errCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: errCode, Message: message})
}

