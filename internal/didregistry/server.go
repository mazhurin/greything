package didregistry

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"greything/internal/did"
	"greything/internal/store"
	"greything/internal/types"
)

type Server struct {
	Store   *store.MemoryStore
	Host    string // e.g. "greything.com"
	BaseURL string // e.g. "http://localhost:8080" or httptest server URL
}

func NewHandler(st *store.MemoryStore, host, baseURL string) http.Handler {
	s := &Server{Store: st, Host: host, BaseURL: strings.TrimRight(baseURL, "/")}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users", s.handleCreateUser)
	mux.HandleFunc("/v1/users/", s.handleUserOps)
	mux.HandleFunc("/users/", s.handleDidJSON)
	return mux
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req types.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.RootPublicKeyMultibase == "" {
		http.Error(w, "missing fields", 400)
		return
	}

	userDID := "did:web:" + s.Host + ":users:" + req.Username
	u := &store.User{
		Username:   req.Username,
		DID:        userDID,
		RootPubMB:  req.RootPublicKeyMultibase,
		Services:   map[string]string{},
		DeviceKeys: map[string]string{},
		UpdatedAt:  time.Now().UTC(),
	}
	if err := s.Store.CreateUser(u); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}

	resp := types.CreateUserResponse{
		DID:            userDID,
		DIDDocumentURL: s.BaseURL + "/users/" + req.Username + "/did.json",
	}
	writeJSON(w, resp)
}

func (s *Server) handleUserOps(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/users/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		http.Error(w, "bad path", 404)
		return
	}
	username := parts[0]
	op := parts[1]

	switch op {
	case "services":
		if r.Method != http.MethodPut {
			http.Error(w, "method", 405)
			return
		}
		var req types.UpdateServicesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		err := s.Store.UpdateServices(username, map[string]string{
			"pod":     req.Pod,
			"events":  req.Events,
			"profile": req.Profile,
		})
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		writeJSON(w, map[string]string{"ok": "true"})
	case "device-keys":
		if r.Method != http.MethodPut {
			http.Error(w, "method", 405)
			return
		}
		var req types.AddDeviceKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if req.DeviceKeyID == "" || req.PublicKeyMultibase == "" {
			http.Error(w, "missing fields", 400)
			return
		}
		if err := s.Store.AddDeviceKey(username, req.DeviceKeyID, req.PublicKeyMultibase); err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		writeJSON(w, map[string]string{"ok": "true"})
	default:
		http.Error(w, "not found", 404)
	}
}

func (s *Server) handleDidJSON(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/did.json") {
		http.Error(w, "not found", 404)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/users/")
	rest = strings.TrimSuffix(rest, "/did.json")
	rest = strings.TrimSuffix(rest, "/")
	username := rest

	u, ok := s.Store.GetUser(username)
	if !ok {
		http.Error(w, "not found", 404)
		return
	}

	doc := did.Build(u.DID, u.RootPubMB, u.Services, u.DeviceKeys)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
