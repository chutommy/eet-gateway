package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"go.uber.org/multierr"
)

// Service is a server of the EET Gateway.
type Service interface {
	ListenAndServe(duration time.Duration)
}

type httpService struct {
	server *http.Server
}

// ListenAndServe runs the server and handles incoming requests. The server can
// be manually shutdown with system calls like: interrupt, termination or kill signals.
// The server is then gracefully shutdown with the given timeout. After the timeout
// exceeds the server is forcefully shutdown.
func (s *httpService) ListenAndServe(timeout time.Duration) {
	log.Info().
		Timestamp().
		Str("action", "listen and serve").
		Str("status", "online").
		Send()
	defer log.Info().
		Timestamp().
		Str("action", "exit service").
		Str("status", "offline").
		Send()

	var err error
	stop := make(chan os.Signal, 1)
	exit := make(chan struct{}, 1)

	// non blocking server
	go func() {
		e := s.server.ListenAndServe()
		if !errors.Is(e, http.ErrServerClosed) {
			multierr.AppendInto(&err, e)
			stop <- syscall.SIGABRT
		}

		exit <- struct{}{}
	}()

	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM) // SIGKILL cannot be handled
	sig := <-stop                                        // block

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	log.Info().
		Str("action", "shutting down").
		Str("status", sig.String()).
		Str("timeout", timeout.String()).
		Send()

	if e := s.server.Shutdown(ctx); e != nil {
		multierr.AppendInto(&err, e)
	}

	<-exit
	if err != nil {
		log.Error().
			Timestamp().
			Err(err).
			Send()
	}
}

// NewService returns a Service implementation with the given HTTP server.
func NewService(server *http.Server) Service {
	return &httpService{
		server: server,
	}
}
