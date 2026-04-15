package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]int // token → userID
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]int),
	}
}

func (s *SessionStore) Create(userID int) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = userID
	s.mu.Unlock()
	return token, nil
}

func (s *SessionStore) Lookup(token string) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userID, ok := s.sessions[token]
	return userID, ok
}

func (s *SessionStore) Delete(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[token]
	if ok {
		delete(s.sessions, token)
	}
	return ok
}
