package server

import (
	"errors"
	"net/http"

	"github.com/chutommy/eetgateway/pkg/gateway"
)

// ErrUnexpected is returned if unexpected error is raised.
var ErrUnexpected = errors.New("unexpected error")

// Handler provides handling options for incoming requests.
type Handler interface {
	HTTPHandler() http.Handler
}

type handler struct {
	gatewaySvc gateway.Service
}

// NewHandler returns an HTTP Handler implementation.
func NewHandler(gatewaySvc gateway.Service) Handler {
	return &handler{
		gatewaySvc: gatewaySvc,
	}
}
