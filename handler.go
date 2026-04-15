package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

type contextKey int

const contextKeyUserID contextKey = iota

type Handler struct {
	store        *Store
	userStore    *UserStore
	sessionStore *SessionStore
}

func NewHandler(store *Store, userStore *UserStore, sessionStore *SessionStore) *Handler {
	return &Handler{store: store, userStore: userStore, sessionStore: sessionStore}
}

// requireAuth is middleware that validates the Bearer token and injects the
// authenticated user's ID into the request context.
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		userID, ok := h.sessionStore.Lookup(token)
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}
		ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
		next(w, r.WithContext(ctx))
	}
}

// contextUserID retrieves the authenticated user's ID from the request context.
func contextUserID(r *http.Request) int {
	id, _ := r.Context().Value(contextKeyUserID).(int)
	return id
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func parseListID(r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("listID"))
	return id, err == nil
}

// resolveOwnedList parses the listID from the path and verifies the list
// exists and belongs to the authenticated user. On failure it writes the
// appropriate error response and returns (0, false).
func (h *Handler) resolveOwnedList(w http.ResponseWriter, r *http.Request) (int, bool) {
	listID, ok := parseListID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid list id")
		return 0, false
	}
	list, ok := h.store.GetList(listID)
	if !ok || list.OwnerID != contextUserID(r) {
		writeError(w, http.StatusNotFound, "list not found")
		return 0, false
	}
	return listID, true
}

// resolveEditableList parses the listID from the path and verifies the list
// exists and the authenticated user is the owner or an invited editor.
func (h *Handler) resolveEditableList(w http.ResponseWriter, r *http.Request) (int, bool) {
	listID, ok := parseListID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid list id")
		return 0, false
	}
	userID := contextUserID(r)
	list, ok := h.store.GetList(listID)
	if !ok {
		writeError(w, http.StatusNotFound, "list not found")
		return 0, false
	}
	if list.OwnerID != userID && !h.store.IsEditor(listID, userID) {
		writeError(w, http.StatusNotFound, "list not found")
		return 0, false
	}
	return listID, true
}

func (h *Handler) listLists(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.store.ListsAccessibleTo(contextUserID(r)))
}

func (h *Handler) createList(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	list := h.store.CreateList(contextUserID(r), body.Name)
	writeJSON(w, http.StatusCreated, list)
}

func (h *Handler) deleteList(w http.ResponseWriter, r *http.Request) {
	listID, ok := h.resolveOwnedList(w, r)
	if !ok {
		return
	}
	h.store.DeleteList(listID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) inviteEditor(w http.ResponseWriter, r *http.Request) {
	listID, ok := h.resolveOwnedList(w, r)
	if !ok {
		return
	}
	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	user, ok := h.userStore.GetByUsername(body.Username)
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if user.ID == contextUserID(r) {
		writeError(w, http.StatusBadRequest, "cannot invite yourself")
		return
	}
	h.store.AddEditor(listID, user.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revokeEditor(w http.ResponseWriter, r *http.Request) {
	listID, ok := h.resolveOwnedList(w, r)
	if !ok {
		return
	}
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	user, ok := h.userStore.GetByUsername(username)
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if !h.store.RemoveEditor(listID, user.ID) {
		writeError(w, http.StatusNotFound, "editor not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listTodos(w http.ResponseWriter, r *http.Request) {
	listID, ok := h.resolveEditableList(w, r)
	if !ok {
		return
	}
	todos, _ := h.store.List(listID)
	writeJSON(w, http.StatusOK, todos)
}

func (h *Handler) getTodo(w http.ResponseWriter, r *http.Request) {
	listID, ok := h.resolveEditableList(w, r)
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	todo, ok := h.store.Get(listID, id)
	if !ok {
		writeError(w, http.StatusNotFound, "todo not found")
		return
	}
	writeJSON(w, http.StatusOK, todo)
}

func (h *Handler) createTodo(w http.ResponseWriter, r *http.Request) {
	listID, ok := h.resolveEditableList(w, r)
	if !ok {
		return
	}
	var body struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}
	todo, ok := h.store.Create(listID, body.Title)
	if !ok {
		writeError(w, http.StatusNotFound, "list not found")
		return
	}
	writeJSON(w, http.StatusCreated, todo)
}

func (h *Handler) updateTodo(w http.ResponseWriter, r *http.Request) {
	listID, ok := h.resolveEditableList(w, r)
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var body struct {
		Title     string `json:"title"`
		Completed bool   `json:"completed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}
	todo, ok := h.store.Update(listID, id, body.Title, body.Completed)
	if !ok {
		writeError(w, http.StatusNotFound, "todo not found")
		return
	}
	writeJSON(w, http.StatusOK, todo)
}

func (h *Handler) deleteTodo(w http.ResponseWriter, r *http.Request) {
	listID, ok := h.resolveEditableList(w, r)
	if !ok {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if !h.store.Delete(listID, id) {
		writeError(w, http.StatusNotFound, "todo not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) registerUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if len(body.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not process request")
		return
	}
	user, err := h.userStore.CreateUser(body.Username, string(hash))
	if errors.Is(err, ErrUsernameTaken) {
		writeError(w, http.StatusConflict, "username already taken")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if id != contextUserID(r) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	user, ok := h.userStore.GetByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if id != contextUserID(r) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if !h.userStore.DeleteUser(id) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	user, ok := h.userStore.GetByUsername(body.Username)
	if !ok {
		// Use a constant-time failure to avoid username enumeration.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$invalid.hash.padding.to.avoid.timing"), []byte(body.Password)) //nolint:errcheck
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, err := h.sessionStore.Create(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": token,
		"user":  user,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing authorization token")
		return
	}
	if !h.sessionStore.Delete(token) {
		writeError(w, http.StatusUnauthorized, "invalid or expired session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) <= len(prefix) {
		return ""
	}
	return v[len(prefix):]
}
