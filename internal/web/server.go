package web

import (
	"context"
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
	ListenAddr string
	Provider   SessionProvider
	Events     *EventBus
	httpSrv    *http.Server
	listener   net.Listener
	logger     *log.Logger
}

// NewServer creates a Server ready to Start.
func NewServer(addr string, provider SessionProvider, events *EventBus) *Server {
	return &Server{
		ListenAddr: addr,
		Provider:   provider,
		Events:     events,
		logger:     log.New(os.Stderr, "[web] ", log.LstdFlags),
	}
}

// Start builds the mux, binds the listener, and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// REST API routes
	registerAPIRoutes(mux, s.Provider)

	// SSE event stream
	mux.Handle("GET /api/events", s.Events)

	// Embedded static files served under /static/
	staticSub, err := fs.Sub(StaticFS, "static")
	if err != nil {
		return fmt.Errorf("static fs: %w", err)
	}
	fileServer := http.FileServer(http.FS(staticSub))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	// Root redirects to index.html
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/static/index.html", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

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

	if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
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
