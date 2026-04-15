package main

import (
	"sync"
	"time"
)

type Todo struct {
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Completed bool      `json:"completed"`
	CreatedAt time.Time `json:"created_at"`
}

type TodoList struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	OwnerID   int       `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

type listData struct {
	list    TodoList
	todos   map[int]Todo
	editors map[int]bool
	nextID  int
}

type Store struct {
	mu     sync.RWMutex
	lists  map[int]*listData
	nextID int
}

func NewStore() *Store {
	return &Store{
		lists:  make(map[int]*listData),
		nextID: 1,
	}
}

func (s *Store) ListsByOwner(ownerID int) []TodoList {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TodoList, 0)
	for _, ld := range s.lists {
		if ld.list.OwnerID == ownerID {
			out = append(out, ld.list)
		}
	}
	return out
}

// ListsAccessibleTo returns all lists the user owns or has been invited to edit.
func (s *Store) ListsAccessibleTo(userID int) []TodoList {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TodoList, 0)
	for _, ld := range s.lists {
		if ld.list.OwnerID == userID || ld.editors[userID] {
			out = append(out, ld.list)
		}
	}
	return out
}

// IsEditor reports whether userID has editor access to listID.
func (s *Store) IsEditor(listID, userID int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ld, ok := s.lists[listID]
	if !ok {
		return false
	}
	return ld.editors[userID]
}

// AddEditor grants userID editor access to listID.
func (s *Store) AddEditor(listID, editorID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ld, ok := s.lists[listID]
	if !ok {
		return false
	}
	ld.editors[editorID] = true
	return true
}

// RemoveEditor revokes editor access for editorID on listID.
func (s *Store) RemoveEditor(listID, editorID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ld, ok := s.lists[listID]
	if !ok {
		return false
	}
	if !ld.editors[editorID] {
		return false
	}
	delete(ld.editors, editorID)
	return true
}

func (s *Store) GetList(listID int) (TodoList, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ld, ok := s.lists[listID]
	if !ok {
		return TodoList{}, false
	}
	return ld.list, true
}

func (s *Store) CreateList(ownerID int, name string) TodoList {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := TodoList{
		ID:        s.nextID,
		Name:      name,
		OwnerID:   ownerID,
		CreatedAt: time.Now().UTC(),
	}
	s.lists[s.nextID] = &listData{
		list:    l,
		todos:   make(map[int]Todo),
		editors: make(map[int]bool),
		nextID:  1,
	}
	s.nextID++
	return l
}

func (s *Store) DeleteList(listID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.lists[listID]
	if !ok {
		return false
	}
	delete(s.lists, listID)
	return true
}

func (s *Store) List(listID int) ([]Todo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ld, ok := s.lists[listID]
	if !ok {
		return nil, false
	}
	todos := make([]Todo, 0, len(ld.todos))
	for _, t := range ld.todos {
		todos = append(todos, t)
	}
	return todos, true
}

func (s *Store) Get(listID, id int) (Todo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ld, ok := s.lists[listID]
	if !ok {
		return Todo{}, false
	}
	t, ok := ld.todos[id]
	return t, ok
}

func (s *Store) Create(listID int, title string) (Todo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ld, ok := s.lists[listID]
	if !ok {
		return Todo{}, false
	}
	t := Todo{
		ID:        ld.nextID,
		Title:     title,
		Completed: false,
		CreatedAt: time.Now().UTC(),
	}
	ld.todos[ld.nextID] = t
	ld.nextID++
	return t, true
}

func (s *Store) Update(listID, id int, title string, completed bool) (Todo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ld, ok := s.lists[listID]
	if !ok {
		return Todo{}, false
	}
	t, ok := ld.todos[id]
	if !ok {
		return Todo{}, false
	}
	t.Title = title
	t.Completed = completed
	ld.todos[id] = t
	return t, true
}

func (s *Store) Delete(listID, id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ld, ok := s.lists[listID]
	if !ok {
		return false
	}
	_, ok = ld.todos[id]
	if !ok {
		return false
	}
	delete(ld.todos, id)
	return true
}
