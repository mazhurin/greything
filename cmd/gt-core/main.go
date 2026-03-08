package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"greything/internal/gtcore"
	"greything/internal/storage"
)

func main() {
	port := flag.Int("port", 8090, "HTTP port")
	dataPath := flag.String("data-path", "/var/lib/greything/core", "data directory")
	didURL := flag.String("did-url", "https://did.greything.com", "base URL for DID resolution")
	didsInternal := flag.String("dids-internal-url", "", "internal URL for gt-dids (e.g. http://127.0.0.1:8080)")
	flag.Parse()

	adapter, err := storage.NewFilesystemAdapter(*dataPath)
	if err != nil {
		log.Fatalf("Failed to create storage adapter: %v", err)
	}

	resolver := &gtcore.HTTPDIDResolver{
		BaseURL: strings.TrimRight(*didURL, "/"),
	}

	srv := gtcore.NewServer(adapter, resolver)
	srv.DIDSInternalURL = *didsInternal

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("gt-core listening on %s (data: %s, did: %s)", addr, *dataPath, *didURL)
	log.Fatal(http.ListenAndServe(addr, srv.Handler()))
}
