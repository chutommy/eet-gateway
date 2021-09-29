package server

import (
	"net/http"
	"time"
)

// Service is the server abstraction as a service.
type Service interface {
	ListenAndServe() error
}

type httpService struct {
	server *http.Server
}

// ListenAndServe runs the server and handles incoming requests.
func (s *httpService) ListenAndServe() error {
	return s.server.ListenAndServe()
}

// NewService returns a Service implementation.
func NewService(handler Handler, addr string) Service {
	return &httpService{
		server: &http.Server{
			Addr:    addr,
			Handler: handler.handler(),
			// TLSConfig:         nil,
			ReadTimeout:       time.Second * 10,
			ReadHeaderTimeout: time.Second * 2,
			WriteTimeout:      time.Second * 10,
			IdleTimeout:       time.Second * 100,
			MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
		},
	}
}
