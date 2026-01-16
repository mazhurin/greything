package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"greything/internal/crypto"
	"greything/internal/store"
	"greything/internal/types"
)

var st = store.NewMemoryStore()

const listen = ":8082"
const ttl = 6 * time.Hour

// For prototype: DID registry base URL (can override with env var)
var didRegistryBase = envOr("DID_REGISTRY_BASEURL", "http://localhost:8080")

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/events", handleEvents)

	log.Printf("event-stream listening on %s (did-registry=%s)", listen, didRegistryBase)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var e types.Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			http.Error(w, "bad json", 400)
			return
		}

		// Basic validation
		if e.Type == "" || e.Actor == "" || e.ObjectURL == "" {
			http.Error(w, "missing fields (type/actor/object)", 400)
			return
		}
		if e.Signature.KID == "" || e.Signature.Sig == "" || e.Signature.Alg == "" {
			http.Error(w, "missing signature fields", 400)
			return
		}
		if err := crypto.MustAlgEd25519(e.Signature.Alg); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		// If TS omitted by client, set now (or you can reject; for prototype we normalize)
		if e.TS.IsZero() {
			e.TS = time.Now().UTC()
		} else {
			e.TS = e.TS.UTC()
		}

		// Ensure kid matches actor namespace (minimal safety)
		if !strings.HasPrefix(e.Signature.KID, e.Actor+"#") {
			http.Error(w, "kid must be actor DID + #keyId", 400)
			return
		}

		// Cryptographic verification
		if ok, verr := verifyEventSignature(e); verr != nil {
			http.Error(w, "verify error: "+verr.Error(), 400)
			return
		} else if !ok {
			http.Error(w, "invalid signature", 401)
			return
		}

		// Store after verification
		st.AppendEvent(store.EventRow{
			TS:        e.TS,
			Actor:     e.Actor,
			Type:      e.Type,
			ObjectURL: e.ObjectURL,
			KID:       e.Signature.KID,
			Sig:       e.Signature.Sig,
		})
		w.WriteHeader(201)

	case http.MethodGet:
		sinceStr := r.URL.Query().Get("since")
		since := time.Now().UTC().Add(-ttl)
		if sinceStr != "" {
			t, err := time.Parse(time.RFC3339, sinceStr)
			if err == nil {
				since = t.UTC()
			}
		}
		rows := st.ListEventsSince(since, ttl)
		writeJSON(w, rows)

	default:
		http.Error(w, "method", 405)
	}
}

type didDoc struct {
	ID                 string `json:"id"`
	VerificationMethod []struct {
		ID                 string `json:"id"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	} `json:"verificationMethod"`
}

func verifyEventSignature(e types.Event) (bool, error) {
	// Resolve DID doc for actor.
	// Prototype assumption: did:web:greything.com:users:<username>
	username := usernameFromDID(e.Actor)
	if username == "" {
		return false, fmt.Errorf("cannot infer username from actor DID: %s", e.Actor)
	}

	url := didRegistryBase + "/users/" + username + "/did.json"
	docBytes, err := httpGetBytes(url)
	if err != nil {
		return false, fmt.Errorf("fetch did doc: %w", err)
	}

	var doc didDoc
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return false, fmt.Errorf("parse did doc: %w", err)
	}
	if doc.ID != e.Actor {
		return false, fmt.Errorf("did doc id mismatch: got %s want %s", doc.ID, e.Actor)
	}

	pubMB := ""
	for _, vm := range doc.VerificationMethod {
		if vm.ID == e.Signature.KID {
			pubMB = vm.PublicKeyMultibase
			break
		}
	}
	if pubMB == "" {
		return false, fmt.Errorf("kid not found in did doc: %s", e.Signature.KID)
	}

	pub, err := crypto.DecodeMultibaseEd25519Pub(pubMB)
	if err != nil {
		return false, fmt.Errorf("decode pubkey: %w", err)
	}

	msg := crypto.CanonicalEvent(e)
	return crypto.VerifyEd25519(pub, msg, e.Signature.Sig)
}

func usernameFromDID(did string) string {
	// did:web:greything.com:users:anton  -> anton
	// Prototype parser: take substring after last ':'
	i := strings.LastIndex(did, ":")
	if i < 0 || i == len(did)-1 {
		return ""
	}
	return did[i+1:]
}

func httpGetBytes(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
