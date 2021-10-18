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
	r.MaxMultipartMemory = 32 << 10 // 32 KiB

	setValidators()
	r.Use(loggingMiddleware)
	r.Use(recoverMiddleware)

	v1 := r.Group("/v1")
	{
		v1.GET("/ping", h.ping)
		v1.POST("/eet", h.eet)

		v1.POST("/cert", h.storeCert)
		v1.PUT("/cert/id", h.changeID)
		v1.PUT("/cert/password", h.changePassword)
		v1.DELETE("/cert", h.deleteCert)
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

func (h *handler) storeCert(c *gin.Context) {
	// default request
	req := &HTTPCreateCertRequest{
		ID: uuid.New().String(),
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, encodeCreateCertResponse(err, nil))
		return
	}

	err := h.gatewaySvc.Store(c, req.ID, []byte(req.Password), req.PKCS12Data, req.PKCS12Password)
	if err != nil {
		switch {
		case errors.Is(err, eet.ErrInvalidTaxpayerCertificate):
			c.JSON(http.StatusBadRequest, encodeCreateCertResponse(eet.ErrInvalidTaxpayerCertificate, nil))
			return
		case errors.Is(err, eet.ErrCertificateParsing):
			c.JSON(http.StatusInternalServerError, encodeCreateCertResponse(eet.ErrCertificateParsing, nil))
			return
		case errors.Is(err, eet.ErrCertificateAlreadyExists):
			c.JSON(http.StatusConflict, encodeCreateCertResponse(eet.ErrCertificateAlreadyExists, nil))
			return
		case errors.Is(err, eet.ErrCertificateStore):
			c.JSON(http.StatusInternalServerError, encodeCreateCertResponse(eet.ErrCertificateStore, nil))
			return
		}

		c.JSON(http.StatusInternalServerError, encodeCreateCertResponse(ErrUnexpectedFailure, nil))
		return
	}

	c.JSON(http.StatusOK, encodeCreateCertResponse(nil, &req.ID))
}

func (h *handler) changePassword(c *gin.Context) {
	// default request
	req := &HTTPChangePasswordRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, encodeChangePasswordResponse(err, nil))
		return
	}

	err := h.gatewaySvc.ChangePassword(c, req.ID, []byte(req.OldPassword), []byte(req.NewPassword))
	if err != nil {
		switch {
		case errors.Is(err, eet.ErrCertificateNotFound):
			c.JSON(http.StatusNotFound, encodeChangePasswordResponse(eet.ErrCertificateNotFound, nil))
			return
		case errors.Is(err, eet.ErrInvalidCipherKey):
			c.JSON(http.StatusUnauthorized, encodeChangePasswordResponse(eet.ErrInvalidCipherKey, nil))
			return
		case errors.Is(err, eet.ErrCertificateDelete):
			c.JSON(http.StatusInternalServerError, encodeChangePasswordResponse(eet.ErrCertificateDelete, nil))
			return
		}

		c.JSON(http.StatusInternalServerError, encodeChangePasswordResponse(ErrUnexpectedFailure, nil))
		return
	}

	c.JSON(http.StatusOK, encodeChangePasswordResponse(nil, &req.ID))
}

func (h *handler) changeID(c *gin.Context) {
	panic(errors.New("not implemented"))
}

func (h *handler) deleteCert(c *gin.Context) {
	// default request
	req := &HTTPDeleteCertRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, encodeDeleteCertResponse(err, nil))
		return
	}

	err := h.gatewaySvc.Delete(c, req.ID)
	if err != nil {
		switch {
		case errors.Is(err, eet.ErrCertificateNotFound):
			c.JSON(http.StatusNotFound, encodeDeleteCertResponse(eet.ErrCertificateNotFound, nil))
			return
		case errors.Is(err, eet.ErrCertificateDelete):
			c.JSON(http.StatusInternalServerError, encodeDeleteCertResponse(eet.ErrCertificateDelete, nil))
			return
		}

		c.JSON(http.StatusInternalServerError, encodeDeleteCertResponse(ErrUnexpectedFailure, nil))
		return
	}

	c.JSON(http.StatusOK, encodeDeleteCertResponse(nil, &req.ID))
}
