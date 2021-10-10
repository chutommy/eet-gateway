package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ErrUnexpectedFailure is returned if no error was expected but some did occur.
var ErrUnexpectedFailure = errors.New("unexpected error")

// Handler provides handling options for incoming requests.
type Handler interface {
	HTTPHandler() http.Handler
}

type handler struct {
	gatewaySvc eet.GatewayService
}

func (h *handler) HTTPHandler() http.Handler {
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

	setValidators()
	r.Use(h.loggingMiddleware)

	v1 := r.Group("/v1")
	{
		v1.GET("/eet", h.ping)
		v1.POST("/eet", h.eet)
	}

	return r
}

func (h *handler) ping(c *gin.Context) {
	if err := h.gatewaySvc.Ping(); err != nil {
		if errors.Is(err, eet.ErrMFCRConnection) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": eet.ErrMFCRConnection.Error()})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrUnexpectedFailure.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": http.StatusText(http.StatusOK)})
}

func (h *handler) eet(c *gin.Context) {
	// default request
	dateTime := eet.DateTime(time.Now().Truncate(time.Second))
	req := &HTTPRequest{
		UUIDZpravy:   eet.UUIDType(uuid.New().String()),
		DatOdesl:     dateTime,
		PrvniZaslani: true,
		Overeni:      false,
		DatTrzby:     dateTime,
		Rezim:        0,
	}

	// bind to default
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	odpoved, err := h.gatewaySvc.Send(c, req.CertID, encodeRequest(req))
	if err != nil {
		if errors.Is(err, eet.ErrCertificateRetrieval) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": eet.ErrCertificateRetrieval.Error()})
			return
		} else if errors.Is(err, eet.ErrRequestConstruction) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": eet.ErrRequestConstruction.Error()})
			return
		} else if errors.Is(err, eet.ErrMFCRConnection) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": eet.ErrMFCRConnection.Error()})
			return
		} else if errors.Is(err, eet.ErrMFCRResponseParse) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": eet.ErrMFCRResponseParse.Error()})
			return
		} else if errors.Is(err, eet.ErrMFCRResponseVerification) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": eet.ErrMFCRResponseVerification.Error()})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrUnexpectedFailure.Error()})
		return
	}

	c.JSON(http.StatusOK, decodeResponse(odpoved))
}
