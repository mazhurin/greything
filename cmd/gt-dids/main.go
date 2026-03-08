package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"greything/internal/dids"
)

func main() {
	port := flag.Int("port", 8080, "HTTP port")
	didDomain := flag.String("did-domain", "did.greything.com", "DID domain")
	didDocPath := flag.String("did-doc-path", "/var/www/did", "root directory for DID documents")
	storageURL := flag.String("storage-url", "https://storage.greything.com", "gt-core storage URL")
	storageInternal := flag.String("storage-internal-url", "", "internal gt-core URL (e.g. http://127.0.0.1:8090)")
	flag.Parse()

	srv := &dids.Server{
		Domain:             *didDomain,
		DocRoot:            *didDocPath,
		StorageURL:         *storageURL,
		StorageInternalURL: *storageInternal,
	}

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("gt-dids listening on %s (domain: %s, docroot: %s, storage: %s)", addr, *didDomain, *didDocPath, *storageURL)
	log.Fatal(http.ListenAndServe(addr, srv.Handler()))
}
