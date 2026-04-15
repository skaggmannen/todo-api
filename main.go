package main

import (
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/danielgtaylor/huma/v2/humacli"
)

// Options defines CLI flags for the server.
type Options struct {
	Port int `help:"Port to listen on" short:"p" default:"8080"`
}

// newHumaAPI creates and configures a Huma API on the provided mux, registers
// authentication middleware and all routes, and returns the huma.API instance.
func newHumaAPI(mux *http.ServeMux, store *Store, userStore *UserStore, sessionStore *SessionStore) huma.API {
	config := huma.DefaultConfig("Todo API", "1.0.0")
	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearer": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
		},
	}
	api := humago.New(mux, config)
	api.UseMiddleware(authMiddleware(api, sessionStore))
	addRoutes(api, store, userStore, sessionStore)
	return api
}

func main() {
	cli := humacli.New(func(hooks humacli.Hooks, options *Options) {
		store := NewStore()
		userStore := NewUserStore()
		sessionStore := NewSessionStore()

		mux := http.NewServeMux()
		newHumaAPI(mux, store, userStore, sessionStore)

		hooks.OnStart(func() {
			fmt.Printf("Starting server on port %d...\n", options.Port)
			fmt.Printf("API documentation available at http://localhost:%d/docs\n", options.Port)
			if err := http.ListenAndServe(fmt.Sprintf(":%d", options.Port), mux); err != nil {
				panic(err)
			}
		})
	})
	cli.Run()
}
