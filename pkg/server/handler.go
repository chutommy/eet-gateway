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
	if err := h.gatewaySvc.Ping(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "OK"})
}

func (h *handler) eet(c *gin.Context) {
	certID := c.Param("certID")

	var trzba *eet.TrzbaType
	if err := c.ShouldBindJSON(&trzba); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	odpoved, err := h.gatewaySvc.Send(c, certID, trzba)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, odpoved)
}
