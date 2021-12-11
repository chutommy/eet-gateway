package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/multierr"
)

// Service is a server of the EET Gateway.
type Service interface {
	ListenAndServe(tls bool, timeout time.Duration) error
}

type httpService struct {
	server *http.Server
}

// ListenAndServe runs the server and handles incoming requests. The server can
// be manually shutdown with system calls like: interrupt, termination or kill signals.
// The server is then gracefully shutdown with the given timeout. After the timeout
// exceeds the server is forcefully shutdown.
func (s *httpService) ListenAndServe(tls bool, timeout time.Duration) (err error) {
	stop := make(chan os.Signal, 1)

	// non blocking server
	go func() {
		var e error
		if tls {
			e = s.server.ListenAndServeTLS("", "")
		} else {
			e = s.server.ListenAndServe()
		}
		if !errors.Is(e, http.ErrServerClosed) {
			multierr.AppendInto(&err, e)
			stop <- syscall.SIGABRT
		}
	}()

	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM) // SIGKILL cannot be handled
	<-stop                                               // block

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if e := s.server.Shutdown(ctx); e != nil {
		multierr.AppendInto(&err, e)
	}

	return err
}

// NewService returns a Service implementation with the given HTTP server.
func NewService(server *http.Server) Service {
	return &httpService{
		server: server,
	}
}
