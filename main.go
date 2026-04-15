package main

import (
	"log"
	"net/http"
	"os"
)

func newMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("POST /users", h.registerUser)
	mux.HandleFunc("POST /sessions", h.login)

	// Authenticated routes
	mux.HandleFunc("GET /users/{id}", h.requireAuth(h.getUser))
	mux.HandleFunc("DELETE /users/{id}", h.requireAuth(h.deleteUser))
	mux.HandleFunc("DELETE /sessions", h.requireAuth(h.logout))
	mux.HandleFunc("GET /lists", h.requireAuth(h.listLists))
	mux.HandleFunc("POST /lists", h.requireAuth(h.createList))
	mux.HandleFunc("DELETE /lists/{listID}", h.requireAuth(h.deleteList))
	mux.HandleFunc("POST /lists/{listID}/editors", h.requireAuth(h.inviteEditor))
	mux.HandleFunc("DELETE /lists/{listID}/editors/{username}", h.requireAuth(h.revokeEditor))
	mux.HandleFunc("GET /lists/{listID}/todos", h.requireAuth(h.listTodos))
	mux.HandleFunc("POST /lists/{listID}/todos", h.requireAuth(h.createTodo))
	mux.HandleFunc("GET /lists/{listID}/todos/{id}", h.requireAuth(h.getTodo))
	mux.HandleFunc("PUT /lists/{listID}/todos/{id}", h.requireAuth(h.updateTodo))
	mux.HandleFunc("DELETE /lists/{listID}/todos/{id}", h.requireAuth(h.deleteTodo))

	return mux
}

func main() {
	store := NewStore()
	userStore := NewUserStore()
	sessionStore := NewSessionStore()
	h := NewHandler(store, userStore, sessionStore)

	mux := newMux(h)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("Server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
