package storage

import "errors"

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// StorageAdapter is the interface for blob storage backends.
// Implementations must be safe for concurrent use.
type StorageAdapter interface {
	// Get retrieves blob bytes by key.
	// Returns ErrNotFound if key doesn't exist.
	Get(key string) ([]byte, error)

	// Put stores blob bytes at key.
	// Overwrites if key already exists.
	Put(key string, data []byte) error

	// Delete removes blob at key.
	// Returns ErrNotFound if key doesn't exist.
	Delete(key string) error

	// Exists checks if blob exists at key.
	Exists(key string) (bool, error)

	// List returns all keys with given prefix.
	// Used for quota calculation and cleanup.
	List(prefix string) ([]string, error)

	// Size returns total bytes used by keys with given prefix.
	// Used for quota enforcement.
	Size(prefix string) (int64, error)
}

// Meta represents blob metadata stored alongside the blob.
type Meta struct {
	Hash        string   `json:"hash"`              // content hash (sha256-...)
	Owner       string   `json:"owner"`             // owner DID
	ACL         []string `json:"acl"`               // access control list
	ContentType string   `json:"contentType"`       // MIME type
	Size        int64    `json:"size"`              // blob size in bytes
	Storage     string   `json:"storage"`           // "hot" or "cold"
	Created     string   `json:"created"`           // ISO8601 timestamp
	Updated     string   `json:"updated,omitempty"` // ISO8601 timestamp (for ACL updates)
	Sig         string   `json:"sig"`               // Ed25519 signature (base64url)

	// Video-specific fields
	Duration int            `json:"duration,omitempty"`
	Delivery *VideoDelivery `json:"delivery,omitempty"`
}

// VideoDelivery contains video streaming service info.
type VideoDelivery struct {
	Provider string `json:"provider"` // "cloudflare-stream", "mux", etc.
	VideoID  string `json:"videoId"`
	Status   string `json:"status"` // "processing", "ready", "error"
}

// MetaRequest is the request body for creating metadata.
type MetaRequest struct {
	ACL         []string `json:"acl"`
	ContentType string   `json:"contentType"`
	Size        int64    `json:"size"`
	Storage     string   `json:"storage"`
	Duration    int      `json:"duration,omitempty"`
}
