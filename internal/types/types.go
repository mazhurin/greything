package types

import "time"

// --- DID registry ---

type CreateUserRequest struct {
	Username              string `json:"username"`
	RootPublicKeyMultibase string `json:"rootPublicKeyMultibase"`
}

type CreateUserResponse struct {
	DID            string `json:"did"`
	DIDDocumentURL string `json:"didDocumentUrl"`
}

type UpdateServicesRequest struct {
	Pod     string `json:"pod"`
	Events  string `json:"events"`
	Profile string `json:"profile"`
}

type AddDeviceKeyRequest struct {
	DeviceKeyID         string `json:"deviceKeyId"`         // e.g. device-2026-01-10
	PublicKeyMultibase  string `json:"publicKeyMultibase"`  // ed25519 pubkey multibase (base58btc)
}

// For X25519 device encryption keys.
type AddDeviceXKeyRequest struct {
	DeviceKeyID        string `json:"deviceKeyId"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// --- Signed payloads (Post / Event) ---

type Signature struct {
	KID string `json:"kid"` // e.g. did:web:greything.com:users:anton#device-2026-01-10
	Alg string `json:"alg"` // "Ed25519"
	Sig string `json:"sig"` // base64url signature
}

type Post struct {
	Type      string    `json:"type"` // "Post"
	ID        string    `json:"id"`
	Author    string    `json:"author"` // DID
	CreatedAt time.Time `json:"createdAt"`
	Content   string    `json:"content"`
	Signature Signature `json:"signature"`
}

type Event struct {
	Type      string    `json:"type"`   // e.g. "new_post"
	Actor     string    `json:"actor"`  // DID
	ObjectURL string    `json:"object"` // URL to authoritative object in pod
	TS        time.Time `json:"ts"`
	Signature Signature `json:"signature"`
}
