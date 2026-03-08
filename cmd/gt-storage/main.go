package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"greything/internal/storage"
	"greything/internal/storageapi"
)

func main() {
	var (
		hotPath    = flag.String("hot-path", "/var/lib/greything/storage/hot", "Path for hot storage")
		coldPath   = flag.String("cold-path", "/var/lib/greything/storage/cold", "Path for cold storage")
		port       = flag.Int("port", 8083, "HTTP server port")
		didBaseURL = flag.String("did-url", "https://did.greything.com", "Base URL for DID resolution")
	)
	flag.Parse()

	// Initialize hot storage
	hot, err := storage.NewFilesystemAdapter(*hotPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize hot storage: %v\n", err)
		os.Exit(1)
	}
	log.Printf("Hot storage initialized at %s", *hotPath)

	// Initialize cold storage
	cold, err := storage.NewFilesystemAdapter(*coldPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize cold storage: %v\n", err)
		os.Exit(1)
	}
	log.Printf("Cold storage initialized at %s", *coldPath)

	// Create server
	server := storageapi.NewServer(hot, cold, *didBaseURL)

	// Start HTTP server
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting storage server on %s", addr)
	log.Printf("DID resolution URL: %s", *didBaseURL)

	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
