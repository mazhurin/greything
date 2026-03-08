package dids

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ClaimsManifest is stored as a blob in gt-core.
type ClaimsManifest struct {
	Version   int               `json:"version"`
	DID       string            `json:"did"`
	Claims    map[string]string `json:"claims"`
	CreatedAt string            `json:"createdAt"`
}

// ClaimsIndex is stored on disk at {DocRoot}/u/{id}/claims-index.json.
type ClaimsIndex struct {
	DID       string            `json:"did"`
	Claims    map[string]string `json:"claims"`
	HeadHash  string            `json:"headHash"`
	IndexedAt string            `json:"indexedAt"`
}

// ClaimsSearchResult is returned by search/lookup endpoints.
type ClaimsSearchResult struct {
	DID    string            `json:"did"`
	Claims map[string]string `json:"claims"`
}

func (s *Server) handleReindex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}

	// Extract {id} from /api/v1/did/{id}/reindex
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/did/")
	id := strings.TrimSuffix(path, "/reindex")
	if id == "" || strings.Contains(id, "/") {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid DID id in URL")
		return
	}

	// Read body (may be empty for POST reindex)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "cannot read body")
		return
	}

	// Skip auth for internal requests (from gt-core on localhost)
	if r.Header.Get("X-GT-Internal") != "true" {
		_, err = s.authenticate(r, id, body)
		if err != nil {
			ae, ok := err.(*authError)
			if ok {
				errorJSON(w, ae.statusCode, http.StatusText(ae.statusCode), ae.message)
			} else {
				errorJSON(w, http.StatusUnauthorized, "unauthorized", err.Error())
			}
			return
		}
	}

	didStr := fmt.Sprintf("did:web:%s:u:%s", s.Domain, id)
	storageURL := s.StorageInternalURL
	if storageURL == "" {
		storageURL = s.StorageURL
	}
	storageURL = strings.TrimRight(storageURL, "/")

	// GET claims head from gt-core
	headURL := fmt.Sprintf("%s/gt/v1/%s/heads/claims", storageURL, didStr)
	headResp, err := http.Get(headURL)
	if err != nil {
		errorJSON(w, http.StatusBadGateway, "bad_gateway", "cannot reach storage")
		return
	}
	defer headResp.Body.Close()

	if headResp.StatusCode == http.StatusNotFound {
		// No claims head — remove index if exists
		indexPath := filepath.Join(s.DocRoot, "u", id, "claims-index.json")
		os.Remove(indexPath)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "no claims found, index cleared"})
		return
	}
	if headResp.StatusCode != http.StatusOK {
		errorJSON(w, http.StatusBadGateway, "bad_gateway", "storage returned error for claims head")
		return
	}

	var head struct {
		Head string `json:"head"`
	}
	if err := json.NewDecoder(headResp.Body).Decode(&head); err != nil {
		errorJSON(w, http.StatusBadGateway, "bad_gateway", "invalid head response from storage")
		return
	}

	// GET manifest blob from gt-core
	// head.Head is "sha256-{hex}"
	hexHash := strings.TrimPrefix(head.Head, "sha256-")
	blobURL := fmt.Sprintf("%s/gt/v1/%s/blobs/sha256/%s", storageURL, didStr, hexHash)
	blobResp, err := http.Get(blobURL)
	if err != nil {
		errorJSON(w, http.StatusBadGateway, "bad_gateway", "cannot fetch claims blob from storage")
		return
	}
	defer blobResp.Body.Close()

	if blobResp.StatusCode != http.StatusOK {
		errorJSON(w, http.StatusBadGateway, "bad_gateway", "storage returned error for claims blob")
		return
	}

	blobData, err := io.ReadAll(blobResp.Body)
	if err != nil {
		errorJSON(w, http.StatusBadGateway, "bad_gateway", "cannot read claims blob")
		return
	}

	var manifest ClaimsManifest
	if err := json.Unmarshal(blobData, &manifest); err != nil {
		errorJSON(w, http.StatusBadRequest, "bad_request", "invalid claims manifest JSON")
		return
	}

	// Validate: manifest.did must match auth DID
	if manifest.DID != didStr {
		errorJSON(w, http.StatusBadRequest, "bad_request", "manifest DID does not match auth DID")
		return
	}

	// Write claims-index.json
	index := ClaimsIndex{
		DID:       didStr,
		Claims:    manifest.Claims,
		HeadHash:  head.Head,
		IndexedAt: time.Now().UTC().Format(time.RFC3339),
	}

	indexData, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal", "cannot marshal index")
		return
	}

	dirPath := filepath.Join(s.DocRoot, "u", id)
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal", "cannot create directory")
		return
	}

	indexPath := filepath.Join(dirPath, "claims-index.json")
	if err := os.WriteFile(indexPath, indexData, 0o644); err != nil {
		errorJSON(w, http.StatusInternalServerError, "internal", "cannot write index file")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}

	q := r.URL.Query().Get("q")
	if q == "" {
		errorJSON(w, http.StatusBadRequest, "bad_request", "missing q parameter")
		return
	}

	qLower := strings.ToLower(q)
	results := s.scanClaimsIndexes(func(index *ClaimsIndex) bool {
		for key, value := range index.Claims {
			if strings.HasSuffix(key, "_hash") {
				continue // skip hash fields for full-text search
			}
			if strings.Contains(strings.ToLower(value), qLower) {
				return true
			}
		}
		return false
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errorJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}

	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	if key == "" || value == "" {
		errorJSON(w, http.StatusBadRequest, "bad_request", "missing key or value parameter")
		return
	}

	results := s.scanClaimsIndexes(func(index *ClaimsIndex) bool {
		v, ok := index.Claims[key]
		return ok && v == value
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// scanClaimsIndexes reads all claims-index.json files and returns matching results.
// Scans both local DIDs (u/) and external DIDs (ext/).
func (s *Server) scanClaimsIndexes(match func(*ClaimsIndex) bool) []ClaimsSearchResult {
	var results []ClaimsSearchResult

	// Scan local DIDs
	scanDir := func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			indexPath := filepath.Join(dir, entry.Name(), "claims-index.json")
			data, err := os.ReadFile(indexPath)
			if err != nil {
				continue
			}
			var index ClaimsIndex
			if err := json.Unmarshal(data, &index); err != nil {
				continue
			}
			if match(&index) {
				results = append(results, ClaimsSearchResult{
					DID:    index.DID,
					Claims: index.Claims,
				})
			}
		}
	}

	scanDir(filepath.Join(s.DocRoot, "u"))
	scanDir(filepath.Join(s.DocRoot, "ext"))

	return results
}
