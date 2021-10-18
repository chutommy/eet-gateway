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
		if errors.Is(err, eet.ErrFSCRConnection) {
			c.JSON(http.StatusServiceUnavailable, encodePingResponse(eet.ErrFSCRConnection.Error()))
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
		case errors.Is(err, eet.ErrInvalidCertificatePassword):
			c.JSON(http.StatusUnauthorized, encodeEETResponse(eet.ErrInvalidCertificatePassword, nil))
			return
		case errors.Is(err, eet.ErrCertificateGet):
			c.JSON(http.StatusServiceUnavailable, encodeEETResponse(eet.ErrCertificateGet, nil))
			return
		case errors.Is(err, eet.ErrRequestBuild):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrRequestBuild, nil))
			return
		case errors.Is(err, eet.ErrFSCRConnection):
			c.JSON(http.StatusServiceUnavailable, encodeEETResponse(eet.ErrFSCRConnection, nil))
			return
		case errors.Is(err, eet.ErrFSCRResponseParse):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrFSCRResponseParse, nil))
			return
		case errors.Is(err, eet.ErrFSCRResponseVerify):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrFSCRResponseVerify, nil))
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
		case errors.Is(err, eet.ErrInvalidTaxpayersCertificate):
			c.JSON(http.StatusBadRequest, encodeCreateCertResponse(eet.ErrInvalidTaxpayersCertificate, nil))
			return
		case errors.Is(err, eet.ErrCertificateParse):
			c.JSON(http.StatusInternalServerError, encodeCreateCertResponse(eet.ErrCertificateParse, nil))
			return
		case errors.Is(err, eet.ErrIDAlreadyExists):
			c.JSON(http.StatusConflict, encodeCreateCertResponse(eet.ErrIDAlreadyExists, nil))
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
		case errors.Is(err, eet.ErrInvalidCertificatePassword):
			c.JSON(http.StatusUnauthorized, encodeChangePasswordResponse(eet.ErrInvalidCertificatePassword, nil))
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
	// default request
	req := &HTTPChangeIDRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, encodeChangeIDResponse(err, nil))
		return
	}

	err := h.gatewaySvc.ChangeID(c, req.ID, req.NewID)
	if err != nil {
		switch {
		case errors.Is(err, eet.ErrCertificateNotFound):
			c.JSON(http.StatusNotFound, encodeChangeIDResponse(eet.ErrCertificateNotFound, nil))
			return
		case errors.Is(err, eet.ErrIDAlreadyExists):
			c.JSON(http.StatusConflict, encodeChangeIDResponse(eet.ErrIDAlreadyExists, nil))
			return
		case errors.Is(err, eet.ErrCertificatUpdateID):
			c.JSON(http.StatusInternalServerError, encodeChangeIDResponse(eet.ErrCertificatUpdateID, nil))
			return
		}

		c.JSON(http.StatusInternalServerError, encodeChangeIDResponse(ErrUnexpectedFailure, nil))
		return
	}

	c.JSON(http.StatusOK, encodeChangeIDResponse(nil, &req.NewID))
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
