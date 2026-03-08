package gtcore

// Head represents a mutable pointer to a content-addressed blob.
type Head struct {
	Head      string `json:"head"`               // "sha256-abcdef..."
	UpdatedAt string `json:"updatedAt,omitempty"` // RFC3339
}

// HeadUpdateRequest is the body for CAS head updates.
type HeadUpdateRequest struct {
	Expected string `json:"expected"` // "" for initial creation
	Head     string `json:"head"`     // new head value
}

// ErrorResponse is the standard error response body.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// BlobMeta holds per-blob metadata including access control.
type BlobMeta struct {
	ACL         []string `json:"acl"`                   // ["*"], [], or list of DIDs
	ContentType string   `json:"contentType,omitempty"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt,omitempty"`
}

// AuthInfo holds authenticated caller information.
type AuthInfo struct {
	DID string
}
