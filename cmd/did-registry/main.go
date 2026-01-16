package main

import (
	"log"
	"net/http"

	"greything/internal/didregistry"
	"greything/internal/store"
)

const host = "greything.com"
const listen = ":8080"

func main() {
	st := store.NewMemoryStore()
	handler := didregistry.NewHandler(st, host, "http://localhost"+listen)

	log.Printf("did-registry listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, handler))
}
