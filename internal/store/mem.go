package store

import (
	"errors"
	"sync"
	"time"
)

type User struct {
	Username  string
	DID       string
	RootPubMB string

	Services   map[string]string // pod/events/profile/inbox...
	DeviceKeys map[string]string // keyID -> pubMultibase (Ed25519 signing keys)
	DeviceXKeys map[string]string // keyID -> pubMultibase (X25519 encryption keys)

	UpdatedAt time.Time
}

type MemoryStore struct {
	mu     sync.RWMutex
	users  map[string]*User
	events []EventRow
}

type EventRow struct {
	TS        time.Time
	Actor     string
	Type      string
	ObjectURL string
	KID       string
	Sig       string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: map[string]*User{}}
}

func (s *MemoryStore) CreateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[u.Username]; ok {
		return errors.New("user exists")
	}

	// Ensure maps are initialized to avoid nil checks everywhere
	if u.Services == nil {
		u.Services = map[string]string{}
	}
	if u.DeviceKeys == nil {
		u.DeviceKeys = map[string]string{}
	}
	if u.DeviceXKeys == nil {
		u.DeviceXKeys = map[string]string{}
	}

	s.users[u.Username] = u
	return nil
}

func (s *MemoryStore) GetUser(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[username]
	if !ok {
		return nil, false
	}

	// Return a copy + copy maps to avoid external mutation of internal state.
	cp := *u
	cp.Services = copyMap(u.Services)
	cp.DeviceKeys = copyMap(u.DeviceKeys)
	cp.DeviceXKeys = copyMap(u.DeviceXKeys)

	return &cp, true
}

func (s *MemoryStore) UpdateServices(username string, services map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return errors.New("not found")
	}
	if u.Services == nil {
		u.Services = map[string]string{}
	}
	for k, v := range services {
		if v != "" {
			u.Services[k] = v
		}
	}
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *MemoryStore) AddDeviceKey(username, keyID, pubMB string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return errors.New("not found")
	}
	if u.DeviceKeys == nil {
		u.DeviceKeys = map[string]string{}
	}
	u.DeviceKeys[keyID] = pubMB
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *MemoryStore) AddDeviceXKey(username, keyID, pubMB string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[username]
	if !ok {
		return errors.New("not found")
	}
	if u.DeviceXKeys == nil {
		u.DeviceXKeys = map[string]string{}
	}
	u.DeviceXKeys[keyID] = pubMB
	u.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *MemoryStore) AppendEvent(e EventRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *MemoryStore) ListEventsSince(since time.Time, ttl time.Duration) []EventRow {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().UTC().Add(-ttl)
	out := make([]EventRow, 0, 64)
	for _, e := range s.events {
		if e.TS.Before(cutoff) {
			continue
		}
		if e.TS.After(since) || e.TS.Equal(since) {
			out = append(out, e)
		}
	}
	return out
}

func copyMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
