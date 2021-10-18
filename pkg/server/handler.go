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
		v1.GET("/ping", h.pingEET)

		v1.POST("/sale", h.sendSale)

		v1.POST("/cert", h.storeCert)
		v1.PUT("/cert/id", h.updateCertID)
		v1.PUT("/cert/password", h.UpdateCertPassword)
		v1.DELETE("/cert", h.deleteCert)
	}

	return r
}

func (h *handler) pingEET(c *gin.Context) {
	if err := h.gatewaySvc.PingEET(); err != nil {
		if errors.Is(err, eet.ErrFSCRConnection) {
			c.JSON(http.StatusServiceUnavailable, encodePingResponse(eet.ErrFSCRConnection.Error()))
			return
		}

		c.JSON(http.StatusInternalServerError, encodePingResponse(ErrUnexpectedFailure.Error()))
		return
	}

	c.JSON(http.StatusOK, encodePingResponse("online"))
}

func (h *handler) sendSale(c *gin.Context) {
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
		c.JSON(http.StatusBadRequest, encodeEETResponse(err, nil, nil))
		return
	}

	odpoved, err := h.gatewaySvc.SendSale(c, req.CertID, []byte(req.CertPassword), decodeEETRequest(req))
	if err != nil {
		switch {
		case errors.Is(err, eet.ErrCertificateNotFound):
			c.JSON(http.StatusNotFound, encodeEETResponse(eet.ErrCertificateNotFound, nil, nil))
			return
		case errors.Is(err, eet.ErrInvalidCertificatePassword):
			c.JSON(http.StatusUnauthorized, encodeEETResponse(eet.ErrInvalidCertificatePassword, nil, nil))
			return
		case errors.Is(err, eet.ErrCertificateGet):
			c.JSON(http.StatusServiceUnavailable, encodeEETResponse(eet.ErrCertificateGet, nil, nil))
			return
		case errors.Is(err, eet.ErrRequestBuild):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrRequestBuild, nil, nil))
			return
		case errors.Is(err, eet.ErrFSCRConnection):
			c.JSON(http.StatusServiceUnavailable, encodeEETResponse(eet.ErrFSCRConnection, nil, nil))
			return
		case errors.Is(err, eet.ErrFSCRResponseParse):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrFSCRResponseParse, nil, nil))
			return
		case errors.Is(err, eet.ErrFSCRResponseVerify):
			c.JSON(http.StatusInternalServerError, encodeEETResponse(eet.ErrFSCRResponseVerify, nil, nil))
			return
		}

		c.JSON(http.StatusInternalServerError, encodeEETResponse(ErrUnexpectedFailure, nil, nil))
		return
	}

	c.JSON(http.StatusOK, encodeEETResponse(nil, req, odpoved))
}

func (h *handler) storeCert(c *gin.Context) {
	// default request
	req := &HTTPCreateCertRequest{
		CertID: uuid.New().String(),
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, encodeCreateCertResponse(err, nil))
		return
	}

	err := h.gatewaySvc.StoreCert(c, req.CertID, []byte(req.CertPassword), req.PKCS12Data, req.PKCS12Password)
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

	c.JSON(http.StatusOK, encodeCreateCertResponse(nil, &req.CertID))
}

func (h *handler) UpdateCertPassword(c *gin.Context) {
	// default request
	req := &HTTPChangePasswordRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, encodeChangePasswordResponse(err, nil))
		return
	}

	err := h.gatewaySvc.UpdateCertPassword(c, req.CertID, []byte(req.CertPassword), []byte(req.NewPassword))
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

	c.JSON(http.StatusOK, encodeChangePasswordResponse(nil, &req.CertID))
}

func (h *handler) updateCertID(c *gin.Context) {
	// default request
	req := &HTTPChangeIDRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, encodeChangeIDResponse(err, nil))
		return
	}

	err := h.gatewaySvc.UpdateCertID(c, req.CertID, req.NewID)
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

	err := h.gatewaySvc.DeleteID(c, req.CertID)
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

	c.JSON(http.StatusOK, encodeDeleteCertResponse(nil, &req.CertID))
}
