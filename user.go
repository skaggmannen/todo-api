package main

import (
	"errors"
	"sync"
	"time"
)

var ErrUsernameTaken = errors.New("username already taken")

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

type UserStore struct {
	mu     sync.RWMutex
	users  map[int]*User
	byName map[string]*User
	nextID int
}

func NewUserStore() *UserStore {
	return &UserStore{
		users:  make(map[int]*User),
		byName: make(map[string]*User),
		nextID: 1,
	}
}

func (s *UserStore) CreateUser(username, passwordHash string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byName[username]; exists {
		return User{}, ErrUsernameTaken
	}
	u := &User{
		ID:           s.nextID,
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
	}
	s.users[s.nextID] = u
	s.byName[username] = u
	s.nextID++
	return *u, nil
}

func (s *UserStore) GetByID(id int) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return User{}, false
	}
	return *u, true
}

func (s *UserStore) GetByUsername(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byName[username]
	if !ok {
		return User{}, false
	}
	return *u, true
}

func (s *UserStore) DeleteUser(id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return false
	}
	delete(s.byName, u.Username)
	delete(s.users, id)
	return true
}
