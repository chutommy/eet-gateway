package server

import (
	"net/http"
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

// NewService returns a Service implementation with the given HTTP server.
func NewService(server *http.Server) Service {
	return &httpService{
		server: server,
	}
}
