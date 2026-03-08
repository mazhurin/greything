package gtcore

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"greything/internal/storage"
)

var ErrConflict = errors.New("conflict")

// HeadStore manages mutable head pointers with CAS semantics.
type HeadStore struct {
	adapter storage.StorageAdapter
	mu      sync.Mutex
}

// NewHeadStore creates a new head store backed by the given adapter.
func NewHeadStore(adapter storage.StorageAdapter) *HeadStore {
	return &HeadStore{adapter: adapter}
}

// headKey returns the storage key for a head.
func headKey(did, name string) string {
	return did + "/heads/" + name
}

// GetHead retrieves a head pointer.
func (h *HeadStore) GetHead(did, name string) (*Head, error) {
	data, err := h.adapter.Get(headKey(did, name))
	if err != nil {
		return nil, err // returns storage.ErrNotFound if missing
	}

	var head Head
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, err
	}
	return &head, nil
}

// UpdateHead performs a CAS update on a head pointer.
// Returns ErrConflict if the expected value doesn't match.
func (h *HeadStore) UpdateHead(did, name string, req HeadUpdateRequest) (*Head, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	key := headKey(did, name)
	current, err := h.adapter.Get(key)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}

	if errors.Is(err, storage.ErrNotFound) {
		// Head doesn't exist — expected must be empty for creation
		if req.Expected != "" {
			return nil, ErrConflict
		}
	} else {
		// Head exists — expected must match current
		var existing Head
		if err := json.Unmarshal(current, &existing); err != nil {
			return nil, err
		}
		if existing.Head != req.Expected {
			return nil, ErrConflict
		}
	}

	newHead := Head{
		Head:      req.Head,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(newHead)
	if err != nil {
		return nil, err
	}

	if err := h.adapter.Put(key, data); err != nil {
		return nil, err
	}

	return &newHead, nil
}
