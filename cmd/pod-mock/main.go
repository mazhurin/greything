package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const listen = ":8081"
const baseDir = "data/pods"

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/u/", handleObjects)

	log.Printf("pod-mock listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func handleObjects(w http.ResponseWriter, r *http.Request) {
	// PUT/GET /u/{username}/objects/{objectId}
	rest := strings.TrimPrefix(r.URL.Path, "/u/")
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || parts[1] != "objects" {
		http.Error(w, "bad path", 404)
		return
	}
	username := parts[0]
	objectID := parts[2]

	path := filepath.Join(baseDir, username, objectID+".json")
	if r.Method == http.MethodPut {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			http.Error(w, "mkdir", 500)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", 400)
			return
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			http.Error(w, "write", 500)
			return
		}
		w.WriteHeader(201)
		return
	}
	if r.Method == http.MethodGet {
		b, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
		return
	}
	http.Error(w, "method", 405)
}
