package server

import (
	"net/http"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/gin-gonic/gin"
)

// Handle abstracts requests handling options.
type Handler interface {
	handler() http.Handler
}

type handler struct {
	gatewaySvc eet.GatewayService
}

func (h *handler) handler() http.Handler {
	return h.ginEngine()
}

// NewHandler returns an HTTP Handler implementation.
func NewHandler(gatewaySvc eet.GatewayService) Handler {
	return &handler{
		gatewaySvc: gatewaySvc,
	}
}

func (h *handler) ginEngine() *gin.Engine {
	r := gin.New()

	v1 := r.Group("/v1")
	v1.GET("/ping", h.ping)
	v1.POST("/eet/:certID", h.eet)

	return r
}

func (h *handler) ping(c *gin.Context) {
	panic("not implemented") // TODO
}

func (h *handler) eet(c *gin.Context) {
	panic("not implemented") // TODO
}
