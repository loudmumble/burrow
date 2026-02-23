package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// Server is the combined HTTP server for the Burrow dashboard.
// It serves the REST API, SSE event stream, and embedded static files.
type Server struct {
	ListenAddr  string
	Provider    SessionProvider
	Events      *EventBus
	APIToken    string
	EnableAPI   bool
	TLSConfig   *tls.Config
	EnableWebUI bool
	httpSrv     *http.Server
	listener    net.Listener
	logger      *log.Logger
}

// NewServer creates a Server ready to Start.
func NewServer(addr string, provider SessionProvider, events *EventBus, apiToken string, enableAPI bool, tlsCfg *tls.Config, enableWebUI bool) *Server {
	return &Server{
		ListenAddr:  addr,
		Provider:    provider,
		Events:      events,
		APIToken:    apiToken,
		EnableAPI:   enableAPI,
		TLSConfig:   tlsCfg,
		EnableWebUI: enableWebUI,
		logger:      log.New(os.Stderr, "[web] ", log.LstdFlags),
	}
}

// Start builds the mux, binds the listener, and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// REST API routes (only register if enabled)
	if s.EnableAPI {
		registerAPIRoutes(mux, s.Provider, s.APIToken)
	}

	// SSE event stream (Also protected by AuthMiddleware to prevent unauthorized event snooping)
	h := &apiHandler{apiToken: s.APIToken}
	mux.HandleFunc("GET /api/events", h.AuthMiddleware(s.Events))

	// Root handler - conditionally serve WebUI
	if s.EnableWebUI {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				// We keep query parameters to pass the token
				query := r.URL.RawQuery
				dest := "/static/index.html"
				if query != "" {
					dest += "?" + query
				}
				http.Redirect(w, r, dest, http.StatusFound)
				return
			}
			http.NotFound(w, r)
		})

		// Embedded static files served under /static/
		staticSub, err := fs.Sub(StaticFS, "static")
		if err != nil {
			return fmt.Errorf("static fs: %w", err)
		}
		fileServer := http.FileServer(http.FS(staticSub))
		mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}

	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln

	s.httpSrv = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE needs unlimited write time
		IdleTimeout:  120 * time.Second,
	}

	s.logger.Printf("listening on %s", ln.Addr())

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	if s.TLSConfig != nil {
		s.httpSrv.TLSConfig = s.TLSConfig
		if err := s.httpSrv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			return err
		}
	} else {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			return err
		}
	}
	return nil
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop() error {
	if s.httpSrv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.logger.Printf("shutting down")
	return s.httpSrv.Shutdown(ctx)
}

// Addr returns the listener address once the server has started.
// Returns empty string if not yet listening.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}
