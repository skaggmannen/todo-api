package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"golang.org/x/crypto/bcrypt"
)

// --- Context keys ---

type contextKey int

const (
	contextKeyUserID contextKey = iota
	contextKeyToken
)

// --- Handler ---

type Handler struct {
	store        *Store
	userStore    *UserStore
	sessionStore *SessionStore
}

// --- Auth middleware ---

// authMiddleware validates Bearer tokens for operations that declare
// "bearer" security, and injects the authenticated user ID and raw token into
// the request context.
func authMiddleware(api huma.API, sessions *SessionStore) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		required := false
		for _, scheme := range ctx.Operation().Security {
			if _, ok := scheme["bearer"]; ok {
				required = true
				break
			}
		}
		if !required {
			next(ctx)
			return
		}

		authHeader := ctx.Header("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) || len(authHeader) == len(prefix) {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "authentication required")
			return
		}
		token := authHeader[len(prefix):]

		userID, ok := sessions.Lookup(token)
		if !ok {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid or expired session")
			return
		}

		ctx = huma.WithValue(ctx, contextKeyUserID, userID)
		ctx = huma.WithValue(ctx, contextKeyToken, token)
		next(ctx)
	}
}

// --- Input / output types ---

// Users
type RegisterUserInput struct {
	Body struct {
		Username string `json:"username" minLength:"1" doc:"Unique username"`
		Password string `json:"password" minLength:"8" doc:"Password (minimum 8 characters)"`
	}
}
type RegisterUserOutput struct{ Body User }

type GetUserInput struct {
	ID int `path:"id" doc:"User ID"`
}
type GetUserOutput struct{ Body User }

type DeleteUserInput struct {
	ID int `path:"id" doc:"User ID"`
}

// Sessions
type LoginInput struct {
	Body struct {
		Username string `json:"username" minLength:"1"`
		Password string `json:"password" minLength:"1"`
	}
}
type LoginResponseBody struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
type LoginOutput struct{ Body LoginResponseBody }

// Lists
type CreateListInput struct {
	Body struct {
		Name string `json:"name" minLength:"1" doc:"List name"`
	}
}
type CreateListOutput struct{ Body TodoList }

type DeleteListInput struct {
	ListID int `path:"listID" doc:"List ID"`
}

type ListListsOutput struct{ Body []TodoList }

// Editors
type InviteEditorInput struct {
	ListID int `path:"listID" doc:"List ID"`
	Body   struct {
		Username string `json:"username" minLength:"1" doc:"Username to invite"`
	}
}

type RevokeEditorInput struct {
	ListID   int    `path:"listID" doc:"List ID"`
	Username string `path:"username" doc:"Username to revoke"`
}

// Todos
type ListTodosInput struct {
	ListID int `path:"listID" doc:"List ID"`
}
type ListTodosOutput struct{ Body []Todo }

type GetTodoInput struct {
	ListID int `path:"listID" doc:"List ID"`
	ID     int `path:"id" doc:"Todo ID"`
}
type GetTodoOutput struct{ Body Todo }

type CreateTodoInput struct {
	ListID int `path:"listID" doc:"List ID"`
	Body   struct {
		Title string `json:"title" minLength:"1" doc:"Todo title"`
	}
}
type CreateTodoOutput struct{ Body Todo }

type UpdateTodoInput struct {
	ListID int `path:"listID" doc:"List ID"`
	ID     int `path:"id" doc:"Todo ID"`
	Body   struct {
		Title     string `json:"title" minLength:"1" doc:"Todo title"`
		Completed bool   `json:"completed" doc:"Completion status"`
	}
}
type UpdateTodoOutput struct{ Body Todo }

type DeleteTodoInput struct {
	ListID int `path:"listID" doc:"List ID"`
	ID     int `path:"id" doc:"Todo ID"`
}

// --- Handlers ---

func (h *Handler) registerUser(ctx context.Context, input *RegisterUserInput) (*RegisterUserOutput, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Body.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, huma.Error500InternalServerError("could not process request")
	}
	user, err := h.userStore.CreateUser(input.Body.Username, string(hash))
	if errors.Is(err, ErrUsernameTaken) {
		return nil, huma.Error409Conflict("username already taken")
	}
	if err != nil {
		return nil, huma.Error500InternalServerError("could not create user")
	}
	return &RegisterUserOutput{Body: user}, nil
}

func (h *Handler) getUser(ctx context.Context, input *GetUserInput) (*GetUserOutput, error) {
	if input.ID != ctx.Value(contextKeyUserID).(int) {
		return nil, huma.Error403Forbidden("access denied")
	}
	user, ok := h.userStore.GetByID(input.ID)
	if !ok {
		return nil, huma.Error404NotFound("user not found")
	}
	return &GetUserOutput{Body: user}, nil
}

func (h *Handler) deleteUser(ctx context.Context, input *DeleteUserInput) (*struct{}, error) {
	if input.ID != ctx.Value(contextKeyUserID).(int) {
		return nil, huma.Error403Forbidden("access denied")
	}
	if !h.userStore.DeleteUser(input.ID) {
		return nil, huma.Error404NotFound("user not found")
	}
	return nil, nil
}

func (h *Handler) login(ctx context.Context, input *LoginInput) (*LoginOutput, error) {
	user, ok := h.userStore.GetByUsername(input.Body.Username)
	if !ok {
		// Constant-time failure to avoid username enumeration.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$invalid.hash.padding.to.avoid.timing"), []byte(input.Body.Password)) //nolint:errcheck
		return nil, huma.Error401Unauthorized("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Body.Password)); err != nil {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}
	token, err := h.sessionStore.Create(user.ID)
	if err != nil {
		return nil, huma.Error500InternalServerError("could not create session")
	}
	return &LoginOutput{Body: LoginResponseBody{Token: token, User: user}}, nil
}

func (h *Handler) logout(ctx context.Context, _ *struct{}) (*struct{}, error) {
	token, _ := ctx.Value(contextKeyToken).(string)
	h.sessionStore.Delete(token)
	return nil, nil
}

func (h *Handler) listLists(ctx context.Context, _ *struct{}) (*ListListsOutput, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	return &ListListsOutput{Body: h.store.ListsAccessibleTo(userID)}, nil
}

func (h *Handler) createList(ctx context.Context, input *CreateListInput) (*CreateListOutput, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list := h.store.CreateList(userID, input.Body.Name)
	return &CreateListOutput{Body: list}, nil
}

func (h *Handler) deleteList(ctx context.Context, input *DeleteListInput) (*struct{}, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list, ok := h.store.GetList(input.ListID)
	if !ok || list.OwnerID != userID {
		return nil, huma.Error404NotFound("list not found")
	}
	h.store.DeleteList(input.ListID)
	return nil, nil
}

func (h *Handler) inviteEditor(ctx context.Context, input *InviteEditorInput) (*struct{}, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list, ok := h.store.GetList(input.ListID)
	if !ok || list.OwnerID != userID {
		return nil, huma.Error404NotFound("list not found")
	}
	user, ok := h.userStore.GetByUsername(input.Body.Username)
	if !ok {
		return nil, huma.Error404NotFound("user not found")
	}
	if user.ID == userID {
		return nil, huma.Error400BadRequest("cannot invite yourself")
	}
	h.store.AddEditor(input.ListID, user.ID)
	return nil, nil
}

func (h *Handler) revokeEditor(ctx context.Context, input *RevokeEditorInput) (*struct{}, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list, ok := h.store.GetList(input.ListID)
	if !ok || list.OwnerID != userID {
		return nil, huma.Error404NotFound("list not found")
	}
	user, ok := h.userStore.GetByUsername(input.Username)
	if !ok {
		return nil, huma.Error404NotFound("user not found")
	}
	if !h.store.RemoveEditor(input.ListID, user.ID) {
		return nil, huma.Error404NotFound("editor not found")
	}
	return nil, nil
}

func (h *Handler) listTodos(ctx context.Context, input *ListTodosInput) (*ListTodosOutput, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list, ok := h.store.GetList(input.ListID)
	if !ok || (list.OwnerID != userID && !h.store.IsEditor(input.ListID, userID)) {
		return nil, huma.Error404NotFound("list not found")
	}
	todos, _ := h.store.List(input.ListID)
	return &ListTodosOutput{Body: todos}, nil
}

func (h *Handler) getTodo(ctx context.Context, input *GetTodoInput) (*GetTodoOutput, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list, ok := h.store.GetList(input.ListID)
	if !ok || (list.OwnerID != userID && !h.store.IsEditor(input.ListID, userID)) {
		return nil, huma.Error404NotFound("list not found")
	}
	todo, ok := h.store.Get(input.ListID, input.ID)
	if !ok {
		return nil, huma.Error404NotFound("todo not found")
	}
	return &GetTodoOutput{Body: todo}, nil
}

func (h *Handler) createTodo(ctx context.Context, input *CreateTodoInput) (*CreateTodoOutput, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list, ok := h.store.GetList(input.ListID)
	if !ok || (list.OwnerID != userID && !h.store.IsEditor(input.ListID, userID)) {
		return nil, huma.Error404NotFound("list not found")
	}
	todo, ok := h.store.Create(input.ListID, input.Body.Title)
	if !ok {
		return nil, huma.Error404NotFound("list not found")
	}
	return &CreateTodoOutput{Body: todo}, nil
}

func (h *Handler) updateTodo(ctx context.Context, input *UpdateTodoInput) (*UpdateTodoOutput, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list, ok := h.store.GetList(input.ListID)
	if !ok || (list.OwnerID != userID && !h.store.IsEditor(input.ListID, userID)) {
		return nil, huma.Error404NotFound("list not found")
	}
	todo, ok := h.store.Update(input.ListID, input.ID, input.Body.Title, input.Body.Completed)
	if !ok {
		return nil, huma.Error404NotFound("todo not found")
	}
	return &UpdateTodoOutput{Body: todo}, nil
}

func (h *Handler) deleteTodo(ctx context.Context, input *DeleteTodoInput) (*struct{}, error) {
	userID := ctx.Value(contextKeyUserID).(int)
	list, ok := h.store.GetList(input.ListID)
	if !ok || (list.OwnerID != userID && !h.store.IsEditor(input.ListID, userID)) {
		return nil, huma.Error404NotFound("list not found")
	}
	if !h.store.Delete(input.ListID, input.ID) {
		return nil, huma.Error404NotFound("todo not found")
	}
	return nil, nil
}

// --- Route registration ---

var bearerSecurity = []map[string][]string{{"bearer": []string{}}}

// addRoutes registers all API operations against the provided huma.API.
func addRoutes(api huma.API, store *Store, userStore *UserStore, sessionStore *SessionStore) {
	h := &Handler{store: store, userStore: userStore, sessionStore: sessionStore}

	huma.Register(api, huma.Operation{
		OperationID:   "register-user",
		Method:        http.MethodPost,
		Path:          "/users",
		Summary:       "Register a new user",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusCreated,
	}, h.registerUser)

	huma.Register(api, huma.Operation{
		OperationID: "get-user",
		Method:      http.MethodGet,
		Path:        "/users/{id}",
		Summary:     "Get a user by ID",
		Tags:        []string{"Users"},
		Security:    bearerSecurity,
	}, h.getUser)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-user",
		Method:        http.MethodDelete,
		Path:          "/users/{id}",
		Summary:       "Delete a user",
		Tags:          []string{"Users"},
		Security:      bearerSecurity,
		DefaultStatus: http.StatusNoContent,
	}, h.deleteUser)

	huma.Register(api, huma.Operation{
		OperationID:   "login",
		Method:        http.MethodPost,
		Path:          "/sessions",
		Summary:       "Login and create a session",
		Tags:          []string{"Auth"},
		DefaultStatus: http.StatusCreated,
	}, h.login)

	huma.Register(api, huma.Operation{
		OperationID:   "logout",
		Method:        http.MethodDelete,
		Path:          "/sessions",
		Summary:       "Logout and invalidate the session",
		Tags:          []string{"Auth"},
		Security:      bearerSecurity,
		DefaultStatus: http.StatusNoContent,
	}, h.logout)

	huma.Register(api, huma.Operation{
		OperationID: "list-lists",
		Method:      http.MethodGet,
		Path:        "/lists",
		Summary:     "List all accessible todo lists",
		Tags:        []string{"Lists"},
		Security:    bearerSecurity,
	}, h.listLists)

	huma.Register(api, huma.Operation{
		OperationID:   "create-list",
		Method:        http.MethodPost,
		Path:          "/lists",
		Summary:       "Create a todo list",
		Tags:          []string{"Lists"},
		Security:      bearerSecurity,
		DefaultStatus: http.StatusCreated,
	}, h.createList)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-list",
		Method:        http.MethodDelete,
		Path:          "/lists/{listID}",
		Summary:       "Delete a todo list",
		Tags:          []string{"Lists"},
		Security:      bearerSecurity,
		DefaultStatus: http.StatusNoContent,
	}, h.deleteList)

	huma.Register(api, huma.Operation{
		OperationID:   "invite-editor",
		Method:        http.MethodPost,
		Path:          "/lists/{listID}/editors",
		Summary:       "Invite a user as an editor",
		Tags:          []string{"Lists"},
		Security:      bearerSecurity,
		DefaultStatus: http.StatusNoContent,
	}, h.inviteEditor)

	huma.Register(api, huma.Operation{
		OperationID:   "revoke-editor",
		Method:        http.MethodDelete,
		Path:          "/lists/{listID}/editors/{username}",
		Summary:       "Revoke editor access",
		Tags:          []string{"Lists"},
		Security:      bearerSecurity,
		DefaultStatus: http.StatusNoContent,
	}, h.revokeEditor)

	huma.Register(api, huma.Operation{
		OperationID: "list-todos",
		Method:      http.MethodGet,
		Path:        "/lists/{listID}/todos",
		Summary:     "List todos in a list",
		Tags:        []string{"Todos"},
		Security:    bearerSecurity,
	}, h.listTodos)

	huma.Register(api, huma.Operation{
		OperationID:   "create-todo",
		Method:        http.MethodPost,
		Path:          "/lists/{listID}/todos",
		Summary:       "Create a todo in a list",
		Tags:          []string{"Todos"},
		Security:      bearerSecurity,
		DefaultStatus: http.StatusCreated,
	}, h.createTodo)

	huma.Register(api, huma.Operation{
		OperationID: "get-todo",
		Method:      http.MethodGet,
		Path:        "/lists/{listID}/todos/{id}",
		Summary:     "Get a todo by ID",
		Tags:        []string{"Todos"},
		Security:    bearerSecurity,
	}, h.getTodo)

	huma.Register(api, huma.Operation{
		OperationID: "update-todo",
		Method:      http.MethodPut,
		Path:        "/lists/{listID}/todos/{id}",
		Summary:     "Update a todo",
		Tags:        []string{"Todos"},
		Security:    bearerSecurity,
	}, h.updateTodo)

	huma.Register(api, huma.Operation{
		OperationID:   "delete-todo",
		Method:        http.MethodDelete,
		Path:          "/lists/{listID}/todos/{id}",
		Summary:       "Delete a todo",
		Tags:          []string{"Todos"},
		Security:      bearerSecurity,
		DefaultStatus: http.StatusNoContent,
	}, h.deleteTodo)
}
