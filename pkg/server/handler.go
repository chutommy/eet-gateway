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
			c.JSON(http.StatusServiceUnavailable, encodePingResponse(eet.ErrMFCRConnection.Error()))
			return
		}

		c.JSON(http.StatusInternalServerError, encodePingResponse(ErrUnexpectedFailure.Error()))
		return
	}

	c.JSON(http.StatusOK, encodePingResponse("online"))
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
		c.JSON(http.StatusBadRequest, encodeEETResponse(err, nil))
		return
	}

	odpoved, err := h.gatewaySvc.Send(c, req.CertID, []byte(req.CertPassword), decodeEETRequest(req))
	if err != nil {
		switch {
		case errors.Is(err, eet.ErrCertificateNotFound):
			c.JSON(http.StatusNotFound, encodeEETResponse(eet.ErrCertificateNotFound, nil))
			return
		case errors.Is(err, eet.ErrInvalidCipherKey):
			c.JSON(http.StatusUnauthorized, encodeEETResponse(eet.ErrInvalidCipherKey, nil))
			return
		case errors.Is(err, eet.ErrCertificateRetrieval):
			c.JSON(http.StatusServiceUnavailable, encodeEETResponse(eet.ErrCertificateRetrieval, nil))
			return
		case errors.Is(err, eet.ErrRequestConstruction):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrRequestConstruction, nil))
			return
		case errors.Is(err, eet.ErrMFCRConnection):
			c.JSON(http.StatusServiceUnavailable, encodeEETResponse(eet.ErrMFCRConnection, nil))
			return
		case errors.Is(err, eet.ErrMFCRResponseParse):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrMFCRResponseParse, nil))
			return
		case errors.Is(err, eet.ErrMFCRResponseVerification):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrMFCRResponseVerification, nil))
			return
		}

		c.JSON(http.StatusInternalServerError, encodeEETResponse(ErrUnexpectedFailure, nil))
		return
	}

	c.JSON(http.StatusOK, encodeEETResponse(nil, odpoved))
}
