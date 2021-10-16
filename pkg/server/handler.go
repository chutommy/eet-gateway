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
	r.Use(loggingMiddleware)
	r.Use(recoverMiddleware)

	v1 := r.Group("/v1")
	{
		v1.GET("/ping", h.ping)
		v1.POST("/eet", h.eet)
	}

	return r
}

func (h *handler) ping(c *gin.Context) {
	if err := h.gatewaySvc.Ping(); err != nil {
		if errors.Is(err, eet.ErrMFCRConnection) {
			c.JSON(http.StatusServiceUnavailable, decodePingResponse(eet.ErrMFCRConnection.Error()))
			return
		}

		c.JSON(http.StatusInternalServerError, decodePingResponse(ErrUnexpectedFailure.Error()))
		return
	}

	c.JSON(http.StatusOK, decodePingResponse("online"))
}

func (h *handler) eet(c *gin.Context) {
	// default request
	dateTime := eet.DateTime(time.Now().Truncate(time.Second))
	req := &HTTPEETRequest{
		UUIDZpravy:   eet.UUIDType(uuid.New().String()),
		DatOdesl:     dateTime,
		PrvniZaslani: true,
		Overeni:      false,
		DatTrzby:     dateTime,
		Rezim:        0,
	}

	// bind to default
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, decodeEETResponse(err, nil))
		return
	}

	odpoved, err := h.gatewaySvc.Send(c, req.CertID, []byte(req.CertPassword), encodeEETRequest(req))
	if err != nil {
		switch {
		case errors.Is(err, eet.ErrCertificateRetrieval):
			c.JSON(http.StatusServiceUnavailable, decodeEETResponse(eet.ErrCertificateRetrieval, nil))
			return
		case errors.Is(err, eet.ErrRequestConstruction):
			c.JSON(http.StatusInternalServerError, decodeEETResponse(eet.ErrRequestConstruction, nil))
			return
		case errors.Is(err, eet.ErrMFCRConnection):
			c.JSON(http.StatusServiceUnavailable, decodeEETResponse(eet.ErrMFCRConnection, nil))
			return
		case errors.Is(err, eet.ErrMFCRResponseParse):
			c.JSON(http.StatusInternalServerError, decodeEETResponse(eet.ErrMFCRResponseParse, nil))
			return
		case errors.Is(err, eet.ErrMFCRResponseVerification):
			c.JSON(http.StatusInternalServerError, decodeEETResponse(eet.ErrMFCRResponseVerification, nil))
			return
		}

		c.JSON(http.StatusInternalServerError, decodeEETResponse(ErrUnexpectedFailure, nil))
		return
	}

	c.JSON(http.StatusOK, decodeEETResponse(nil, odpoved))
}
