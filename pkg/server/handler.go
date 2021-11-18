package server

import (
	"net/http"

	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/chutommy/eetgateway/pkg/server/httphandler"
)

// Handler provides handling options for incoming requests.
type Handler interface {
	HTTPHandler() http.Handler
}

// NewHTTPHandler returns an HTTP Handler implementation.
func NewHTTPHandler(g gateway.Service) Handler {
	return httphandler.NewHandler(g)
}
