package gtcore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"greything/internal/storage"
)

const (
	maxInboxItemSize = 64 * 1024 // 64 KB
	maxInboxItems    = 200
)

func inboxPrefix(did string) string {
	return did + "/inbox/"
}

func inboxItemKey(did, itemID string) string {
	return did + "/inbox/" + itemID
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	if route.inboxItemID == "" {
		// /gt/v1/{did}/inbox
		switch r.Method {
		case http.MethodPost:
			s.handleInboxPost(w, r, route)
		case http.MethodGet:
			s.handleInboxList(w, r, route)
		default:
			s.errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST")
		}
	} else {
		// /gt/v1/{did}/inbox/{id}
		switch r.Method {
		case http.MethodGet:
			s.handleInboxGet(w, r, route)
		case http.MethodDelete:
			s.handleInboxDelete(w, r, route)
		default:
			s.errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or DELETE")
		}
	}
}

// handleInboxPost accepts an anonymous ciphertext drop. No auth required.
func (s *Server) handleInboxPost(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxInboxItemSize+1))
	if err != nil {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "failed to read body")
		return
	}
	if len(body) > maxInboxItemSize {
		s.errorJSON(w, http.StatusRequestEntityTooLarge, "too_large", "max inbox item size is 64KB")
		return
	}
	if len(body) == 0 {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "empty body")
		return
	}

	// Validate it's JSON with type InboxCiphertextV1
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "body must be valid JSON")
		return
	}
	if envelope.Type != "InboxCiphertextV1" {
		s.errorJSON(w, http.StatusBadRequest, "bad_request", "type must be InboxCiphertextV1")
		return
	}

	// Check inbox size limit
	existing, err := s.store.List(inboxPrefix(route.did))
	if err != nil && !isNotFoundErr(err) {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if len(existing) >= maxInboxItems {
		s.errorJSON(w, http.StatusConflict, "inbox_full", "recipient inbox is full")
		return
	}

	// Generate server-assigned ID: timestamp + random suffix
	now := time.Now().UTC()
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	itemID := now.Format("20060102T150405Z") + "-" + hex.EncodeToString(randBytes)

	key := inboxItemKey(route.did, itemID)
	if err := s.store.Put(key, body); err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": itemID})
}

// handleInboxList returns the list of inbox items. Auth required, owner only.
func (s *Server) handleInboxList(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	auth, _, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	keys, err := s.store.List(inboxPrefix(route.did))
	if err != nil {
		// List returns nil for non-existent prefix (WalkDir handles it)
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	type inboxEntry struct {
		ID   string `json:"id"`
		Size int    `json:"size"`
	}

	entries := make([]inboxEntry, 0, len(keys))
	prefix := inboxPrefix(route.did)
	for _, k := range keys {
		id := strings.TrimPrefix(k, prefix)
		// Skip any nested paths or temp files
		if strings.Contains(id, "/") || strings.HasSuffix(id, ".tmp") {
			continue
		}
		data, err := s.store.Get(k)
		if err != nil {
			continue
		}
		entries = append(entries, inboxEntry{
			ID:   id,
			Size: len(data),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleInboxGet returns a single inbox item. Auth required, owner only.
func (s *Server) handleInboxGet(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	auth, _, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	key := inboxItemKey(route.did, route.inboxItemID)
	data, err := s.store.Get(key)
	if err != nil {
		if isNotFoundErr(err) {
			s.errorJSON(w, http.StatusNotFound, "not_found", "inbox item not found")
			return
		}
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleInboxDelete removes a single inbox item. Auth required, owner only.
func (s *Server) handleInboxDelete(w http.ResponseWriter, r *http.Request, route *parsedRoute) {
	auth, _, err := Authenticate(r, s.resolver)
	if err != nil {
		s.errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	if auth.DID != route.did {
		s.errorJSON(w, http.StatusForbidden, "forbidden", "not the owner of this namespace")
		return
	}

	key := inboxItemKey(route.did, route.inboxItemID)
	err = s.store.Delete(key)
	if err != nil {
		if isNotFoundErr(err) {
			s.errorJSON(w, http.StatusNotFound, "not_found", "inbox item not found")
			return
		}
		s.errorJSON(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func isNotFoundErr(err error) bool {
	return err == storage.ErrNotFound || (err != nil && strings.Contains(err.Error(), "not found"))
}

// validateInboxItemID checks that the ID looks like a valid server-generated ID.
func validateInboxItemID(id string) error {
	// Format: 20060102T150405Z-a1b2c3d4
	if len(id) < 10 {
		return fmt.Errorf("invalid inbox item ID")
	}
	// Basic sanity: only alphanumeric, dashes, T, Z
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == 'T' || c == 'Z' || c == '-') {
			return fmt.Errorf("invalid character in inbox item ID")
		}
	}
	// Prevent path traversal
	if strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return fmt.Errorf("invalid inbox item ID")
	}
	return nil
}

// sanitizeInboxItemID extracts just the filename component for safety.
func sanitizeInboxItemID(id string) string {
	return path.Base(id)
}
