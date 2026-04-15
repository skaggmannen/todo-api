package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- Test infrastructure ---

type testEnv struct {
	t   *testing.T
	url string
}

func setUp(t *testing.T) *testEnv {
	t.Helper()
	store := NewStore()
	userStore := NewUserStore()
	sessionStore := NewSessionStore()

	mux := http.NewServeMux()
	newHumaAPI(mux, store, userStore, sessionStore)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &testEnv{t: t, url: srv.URL}
}

func (e *testEnv) do(method, path string, body any, token string) *http.Response {
	e.t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatalf("marshal body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, e.url+path, reqBody)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("do request: %v", err)
	}
	return resp
}

func decodeBody(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	got := resp.StatusCode
	resp.Body.Close()
	if got != want {
		t.Errorf("status: got %d, want %d", got, want)
	}
}

// mustRegister creates a user and returns their ID. Fails the test on error.
func (e *testEnv) mustRegister(username, password string) int {
	e.t.Helper()
	resp := e.do("POST", "/users", map[string]string{
		"username": username,
		"password": password,
	}, "")
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		e.t.Fatalf("register %q: got %d, want 201", username, resp.StatusCode)
	}
	var user struct {
		ID int `json:"id"`
	}
	decodeBody(e.t, resp, &user)
	return user.ID
}

// mustLogin authenticates a user and returns the session token. Fails the test on error.
func (e *testEnv) mustLogin(username, password string) string {
	e.t.Helper()
	resp := e.do("POST", "/sessions", map[string]string{
		"username": username,
		"password": password,
	}, "")
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		e.t.Fatalf("login %q: got %d, want 201", username, resp.StatusCode)
	}
	var lr struct {
		Token string `json:"token"`
	}
	decodeBody(e.t, resp, &lr)
	return lr.Token
}

// mustCreateList creates a list and returns its ID. Fails the test on error.
func (e *testEnv) mustCreateList(token, name string) int {
	e.t.Helper()
	resp := e.do("POST", "/lists", map[string]string{"name": name}, token)
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		e.t.Fatalf("create list %q: got %d, want 201", name, resp.StatusCode)
	}
	var list struct {
		ID int `json:"id"`
	}
	decodeBody(e.t, resp, &list)
	return list.ID
}

// mustCreateTodo creates a todo and returns its ID. Fails the test on error.
func (e *testEnv) mustCreateTodo(token string, listID int, title string) int {
	e.t.Helper()
	resp := e.do("POST", fmt.Sprintf("/lists/%d/todos", listID), map[string]string{"title": title}, token)
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		e.t.Fatalf("create todo %q: got %d, want 201", title, resp.StatusCode)
	}
	var todo struct {
		ID int `json:"id"`
	}
	decodeBody(e.t, resp, &todo)
	return todo.ID
}

// mustInviteEditor invites a user as editor to a list. Fails the test on error.
func (e *testEnv) mustInviteEditor(token string, listID int, username string) {
	e.t.Helper()
	resp := e.do("POST", fmt.Sprintf("/lists/%d/editors", listID), map[string]string{"username": username}, token)
	if resp.StatusCode != http.StatusNoContent {
		resp.Body.Close()
		e.t.Fatalf("invite editor %q: got %d, want 204", username, resp.StatusCode)
	}
	resp.Body.Close()
}

// =============================================================================
// User Accounts
// =============================================================================

func TestRegister_ValidUser(t *testing.T) {
	env := setUp(t)
	resp := env.do("POST", "/users", map[string]string{
		"username": "alice",
		"password": "password123",
	}, "")
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("got %d, want 201", resp.StatusCode)
	}
	var user struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
	}
	decodeBody(t, resp, &user)
	if user.Username != "alice" {
		t.Errorf("username: got %q, want %q", user.Username, "alice")
	}
	if user.ID == 0 {
		t.Error("id should be set")
	}
}

func TestRegister_PasswordHashNotExposed(t *testing.T) {
	env := setUp(t)
	resp := env.do("POST", "/users", map[string]string{
		"username": "alice",
		"password": "password123",
	}, "")
	var raw map[string]any
	decodeBody(t, resp, &raw)
	if _, ok := raw["password_hash"]; ok {
		t.Error("password_hash must not be exposed in registration response")
	}
	if _, ok := raw["PasswordHash"]; ok {
		t.Error("PasswordHash must not be exposed in registration response")
	}
}

func TestRegister_DuplicateUsername(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	resp := env.do("POST", "/users", map[string]string{
		"username": "alice",
		"password": "anotherpassword",
	}, "")
	assertStatus(t, resp, http.StatusConflict)
}

func TestRegister_PasswordMinimumLength(t *testing.T) {
	env := setUp(t)

	// Exactly 8 characters should succeed.
	resp := env.do("POST", "/users", map[string]string{
		"username": "alice",
		"password": "exactly8",
	}, "")
	assertStatus(t, resp, http.StatusCreated)

	// 7 characters should be rejected.
	resp = env.do("POST", "/users", map[string]string{
		"username": "bob",
		"password": "short77",
	}, "")
	assertStatus(t, resp, http.StatusUnprocessableEntity)
}

func TestRegister_MissingUsername(t *testing.T) {
	env := setUp(t)
	resp := env.do("POST", "/users", map[string]string{
		"password": "password123",
	}, "")
	assertStatus(t, resp, http.StatusUnprocessableEntity)
}

func TestDeleteUser_OwnAccount(t *testing.T) {
	env := setUp(t)
	id := env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")

	resp := env.do("DELETE", fmt.Sprintf("/users/%d", id), nil, token)
	assertStatus(t, resp, http.StatusNoContent)
}

func TestUser_CannotViewOtherUsersAccount(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	bobID := env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")

	// Alice should not be able to see Bob's account information.
	resp := env.do("GET", fmt.Sprintf("/users/%d", bobID), nil, aliceToken)
	if resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		t.Error("a user must not be able to view another user's account (got 200)")
		return
	}
	resp.Body.Close()
}

func TestUser_CannotDeleteOtherUsersAccount(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	bobID := env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")

	// Alice should not be able to delete Bob's account.
	resp := env.do("DELETE", fmt.Sprintf("/users/%d", bobID), nil, aliceToken)
	if resp.StatusCode == http.StatusNoContent {
		t.Error("a user must not be able to delete another user's account (got 204)")
		return
	}
	resp.Body.Close()
}

// =============================================================================
// Authentication
// =============================================================================

func TestLogin_ValidCredentials(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")

	resp := env.do("POST", "/sessions", map[string]string{
		"username": "alice",
		"password": "password123",
	}, "")
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("got %d, want 201", resp.StatusCode)
	}
	var lr struct {
		Token string `json:"token"`
	}
	decodeBody(t, resp, &lr)
	if lr.Token == "" {
		t.Error("login response must include a non-empty token")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")

	resp := env.do("POST", "/sessions", map[string]string{
		"username": "alice",
		"password": "wrongpassword",
	}, "")
	assertStatus(t, resp, http.StatusUnauthorized)
}

func TestLogin_NonExistentUser(t *testing.T) {
	env := setUp(t)

	resp := env.do("POST", "/sessions", map[string]string{
		"username": "nobody",
		"password": "password123",
	}, "")
	assertStatus(t, resp, http.StatusUnauthorized)
}

func TestAuth_ProtectedRoutesRequireBearerToken(t *testing.T) {
	env := setUp(t)

	routes := []struct{ method, path string }{
		{"GET", "/lists"},
		{"POST", "/lists"},
		{"GET", "/users/1"},
		{"DELETE", "/users/1"},
		{"DELETE", "/sessions"},
	}
	for _, rt := range routes {
		resp := env.do(rt.method, rt.path, nil, "")
		if resp.StatusCode != http.StatusUnauthorized {
			resp.Body.Close()
			t.Errorf("%s %s without token: got %d, want 401", rt.method, rt.path, resp.StatusCode)
			continue
		}
		resp.Body.Close()
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	env := setUp(t)

	resp := env.do("GET", "/lists", nil, "not-a-real-token")
	assertStatus(t, resp, http.StatusUnauthorized)
}

func TestLogout_InvalidatesSessionToken(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")

	// Token works before logout.
	resp := env.do("GET", "/lists", nil, token)
	assertStatus(t, resp, http.StatusOK)

	// Logout.
	resp = env.do("DELETE", "/sessions", nil, token)
	assertStatus(t, resp, http.StatusNoContent)

	// Token must be invalid after logout.
	resp = env.do("GET", "/lists", nil, token)
	assertStatus(t, resp, http.StatusUnauthorized)
}

// =============================================================================
// Todo Lists
// =============================================================================

func TestCreateList_SetsOwner(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")

	resp := env.do("POST", "/lists", map[string]string{"name": "Shopping"}, token)
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("got %d, want 201", resp.StatusCode)
	}
	var list struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		OwnerID int    `json:"owner_id"`
	}
	decodeBody(t, resp, &list)
	if list.Name != "Shopping" {
		t.Errorf("name: got %q, want %q", list.Name, "Shopping")
	}
	if list.OwnerID == 0 {
		t.Error("owner_id should be set on the created list")
	}
}

func TestCreateList_NameRequired(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")

	resp := env.do("POST", "/lists", map[string]string{"name": ""}, token)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
}

func TestListLists_OnlyOwnedOrShared(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")

	env.mustCreateList(aliceToken, "Alice's List")
	env.mustCreateList(bobToken, "Bob's List")

	// Alice should only see her own list.
	resp := env.do("GET", "/lists", nil, aliceToken)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var lists []struct {
		Name string `json:"name"`
	}
	decodeBody(t, resp, &lists)
	if len(lists) != 1 {
		t.Errorf("alice should see 1 list, got %d", len(lists))
	}
	if len(lists) == 1 && lists[0].Name != "Alice's List" {
		t.Errorf("alice should see her own list, got %q", lists[0].Name)
	}
}

func TestDeleteList_OwnerCanDelete(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(token, "My List")

	resp := env.do("DELETE", fmt.Sprintf("/lists/%d", listID), nil, token)
	assertStatus(t, resp, http.StatusNoContent)
}

func TestDeleteList_NonOwnerCannotDelete(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")

	listID := env.mustCreateList(aliceToken, "Alice's List")

	resp := env.do("DELETE", fmt.Sprintf("/lists/%d", listID), nil, bobToken)
	if resp.StatusCode == http.StatusNoContent {
		t.Error("non-owner must not be able to delete the list")
		return
	}
	resp.Body.Close()
}

// =============================================================================
// Collaboration
// =============================================================================

func TestInviteEditor_OwnerCanInvite(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(aliceToken, "Shared List")

	resp := env.do("POST", fmt.Sprintf("/lists/%d/editors", listID),
		map[string]string{"username": "bob"}, aliceToken)
	assertStatus(t, resp, http.StatusNoContent)
}

func TestInviteEditor_CannotInviteSelf(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	aliceToken := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(aliceToken, "My List")

	resp := env.do("POST", fmt.Sprintf("/lists/%d/editors", listID),
		map[string]string{"username": "alice"}, aliceToken)
	assertStatus(t, resp, http.StatusBadRequest)
}

func TestInviteEditor_NonExistentUser(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	aliceToken := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(aliceToken, "My List")

	resp := env.do("POST", fmt.Sprintf("/lists/%d/editors", listID),
		map[string]string{"username": "nobody"}, aliceToken)
	assertStatus(t, resp, http.StatusNotFound)
}

func TestInviteEditor_NonOwnerCannotInvite(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	env.mustRegister("charlie", "password789")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Alice's List")

	// Bob tries to invite Charlie onto Alice's list.
	resp := env.do("POST", fmt.Sprintf("/lists/%d/editors", listID),
		map[string]string{"username": "charlie"}, bobToken)
	if resp.StatusCode == http.StatusNoContent {
		t.Error("non-owner must not be able to invite editors")
		return
	}
	resp.Body.Close()
}

func TestEditor_CanViewTodos(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Shared List")
	env.mustInviteEditor(aliceToken, listID, "bob")

	resp := env.do("GET", fmt.Sprintf("/lists/%d/todos", listID), nil, bobToken)
	assertStatus(t, resp, http.StatusOK)
}

func TestEditor_CanCreateTodo(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Shared List")
	env.mustInviteEditor(aliceToken, listID, "bob")

	resp := env.do("POST", fmt.Sprintf("/lists/%d/todos", listID),
		map[string]string{"title": "Bob's todo"}, bobToken)
	assertStatus(t, resp, http.StatusCreated)
}

func TestEditor_CanUpdateTodo(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Shared List")
	todoID := env.mustCreateTodo(aliceToken, listID, "Original title")
	env.mustInviteEditor(aliceToken, listID, "bob")

	resp := env.do("PUT", fmt.Sprintf("/lists/%d/todos/%d", listID, todoID),
		map[string]any{"title": "Updated title", "completed": true}, bobToken)
	assertStatus(t, resp, http.StatusOK)
}

func TestEditor_CanDeleteTodo(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Shared List")
	todoID := env.mustCreateTodo(aliceToken, listID, "To be deleted")
	env.mustInviteEditor(aliceToken, listID, "bob")

	resp := env.do("DELETE", fmt.Sprintf("/lists/%d/todos/%d", listID, todoID), nil, bobToken)
	assertStatus(t, resp, http.StatusNoContent)
}

func TestRevokeEditor_RemovesAccess(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Shared List")
	env.mustInviteEditor(aliceToken, listID, "bob")

	// Confirm Bob has access.
	resp := env.do("GET", fmt.Sprintf("/lists/%d/todos", listID), nil, bobToken)
	assertStatus(t, resp, http.StatusOK)

	// Revoke Bob's editor access.
	resp = env.do("DELETE", fmt.Sprintf("/lists/%d/editors/bob", listID), nil, aliceToken)
	assertStatus(t, resp, http.StatusNoContent)

	// Bob must no longer have access.
	resp = env.do("GET", fmt.Sprintf("/lists/%d/todos", listID), nil, bobToken)
	if resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		t.Error("revoked editor must not be able to access the list")
		return
	}
	resp.Body.Close()
}

func TestRevokeEditor_NonOwnerCannotRevoke(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	env.mustRegister("charlie", "password789")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Alice's List")
	env.mustInviteEditor(aliceToken, listID, "charlie")

	// Bob (non-owner) tries to revoke Charlie.
	resp := env.do("DELETE", fmt.Sprintf("/lists/%d/editors/charlie", listID), nil, bobToken)
	if resp.StatusCode == http.StatusNoContent {
		t.Error("non-owner must not be able to revoke editor access")
		return
	}
	resp.Body.Close()
}

func TestListLists_IncludesSharedLists(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")

	listID := env.mustCreateList(aliceToken, "Shared List")

	// Before invite, Bob should see no lists.
	resp := env.do("GET", "/lists", nil, bobToken)
	var before []struct{}
	decodeBody(t, resp, &before)
	if len(before) != 0 {
		t.Errorf("before invite: bob should see 0 lists, got %d", len(before))
	}

	// After invite, Bob should see the shared list.
	env.mustInviteEditor(aliceToken, listID, "bob")

	resp = env.do("GET", "/lists", nil, bobToken)
	var after []struct{}
	decodeBody(t, resp, &after)
	if len(after) != 1 {
		t.Errorf("after invite: bob should see 1 list, got %d", len(after))
	}
}

// =============================================================================
// Todos
// =============================================================================

func TestTodo_CreateWithTitle(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(token, "My List")

	resp := env.do("POST", fmt.Sprintf("/lists/%d/todos", listID),
		map[string]string{"title": "Buy milk"}, token)
	if resp.StatusCode != http.StatusCreated {
		resp.Body.Close()
		t.Fatalf("got %d, want 201", resp.StatusCode)
	}
	var todo struct {
		ID        int    `json:"id"`
		Title     string `json:"title"`
		Completed bool   `json:"completed"`
	}
	decodeBody(t, resp, &todo)
	if todo.Title != "Buy milk" {
		t.Errorf("title: got %q, want %q", todo.Title, "Buy milk")
	}
	if todo.Completed {
		t.Error("new todo should not be completed by default")
	}
}

func TestTodo_TitleRequired(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(token, "My List")

	resp := env.do("POST", fmt.Sprintf("/lists/%d/todos", listID),
		map[string]string{"title": ""}, token)
	assertStatus(t, resp, http.StatusUnprocessableEntity)
}

func TestTodo_ListAll(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(token, "My List")
	env.mustCreateTodo(token, listID, "First")
	env.mustCreateTodo(token, listID, "Second")

	resp := env.do("GET", fmt.Sprintf("/lists/%d/todos", listID), nil, token)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var todos []struct {
		Title string `json:"title"`
	}
	decodeBody(t, resp, &todos)
	if len(todos) != 2 {
		t.Errorf("got %d todos, want 2", len(todos))
	}
}

func TestTodo_GetByID(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(token, "My List")
	todoID := env.mustCreateTodo(token, listID, "Buy eggs")

	resp := env.do("GET", fmt.Sprintf("/lists/%d/todos/%d", listID, todoID), nil, token)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var todo struct {
		ID    int    `json:"id"`
		Title string `json:"title"`
	}
	decodeBody(t, resp, &todo)
	if todo.ID != todoID {
		t.Errorf("id: got %d, want %d", todo.ID, todoID)
	}
	if todo.Title != "Buy eggs" {
		t.Errorf("title: got %q, want %q", todo.Title, "Buy eggs")
	}
}

func TestTodo_GetNonExistent(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(token, "My List")

	resp := env.do("GET", fmt.Sprintf("/lists/%d/todos/9999", listID), nil, token)
	assertStatus(t, resp, http.StatusNotFound)
}

func TestTodo_UpdateTitleAndCompleted(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(token, "My List")
	todoID := env.mustCreateTodo(token, listID, "Buy milk")

	resp := env.do("PUT", fmt.Sprintf("/lists/%d/todos/%d", listID, todoID),
		map[string]any{"title": "Buy oat milk", "completed": true}, token)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var todo struct {
		Title     string `json:"title"`
		Completed bool   `json:"completed"`
	}
	decodeBody(t, resp, &todo)
	if todo.Title != "Buy oat milk" {
		t.Errorf("title: got %q, want %q", todo.Title, "Buy oat milk")
	}
	if !todo.Completed {
		t.Error("completed should be true after update")
	}
}

func TestTodo_Delete(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	token := env.mustLogin("alice", "password123")
	listID := env.mustCreateList(token, "My List")
	todoID := env.mustCreateTodo(token, listID, "Buy milk")

	resp := env.do("DELETE", fmt.Sprintf("/lists/%d/todos/%d", listID, todoID), nil, token)
	assertStatus(t, resp, http.StatusNoContent)

	// Verify the todo is gone.
	resp = env.do("GET", fmt.Sprintf("/lists/%d/todos/%d", listID, todoID), nil, token)
	assertStatus(t, resp, http.StatusNotFound)
}

func TestTodo_NonMemberCannotAccess(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Alice's Private List")

	// Bob (not a member) must not be able to access Alice's todos.
	resp := env.do("GET", fmt.Sprintf("/lists/%d/todos", listID), nil, bobToken)
	if resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		t.Error("non-member must not be able to view another user's list todos")
		return
	}
	resp.Body.Close()
}

func TestTodo_NonMemberCannotCreateTodo(t *testing.T) {
	env := setUp(t)
	env.mustRegister("alice", "password123")
	env.mustRegister("bob", "password456")
	aliceToken := env.mustLogin("alice", "password123")
	bobToken := env.mustLogin("bob", "password456")
	listID := env.mustCreateList(aliceToken, "Alice's List")

	resp := env.do("POST", fmt.Sprintf("/lists/%d/todos", listID),
		map[string]string{"title": "Intruder todo"}, bobToken)
	if resp.StatusCode == http.StatusCreated {
		resp.Body.Close()
		t.Error("non-member must not be able to add todos to another user's list")
		return
	}
	resp.Body.Close()
}
