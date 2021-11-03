package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
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

func (h *handler) HTTPHandler() http.Handler {
	return h.ginEngine()
}

// NewHandler returns an HTTP Handler implementation.
func NewHandler(gatewaySvc gateway.Service) Handler {
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
		v1.GET("/ping", h.pingEET)
		logEndpoint(http.MethodGet, "/ping")

		v1.POST("/sale", h.sendSale)
		logEndpoint(http.MethodPost, "/sale")

		v1.POST("/cert", h.storeCert)
		logEndpoint(http.MethodPost, "/cert")
		v1.GET("/cert", h.listCertIDs)
		logEndpoint(http.MethodGet, "/cert")
		v1.PUT("/cert/id", h.updateCertID)
		logEndpoint(http.MethodPut, "/cert/id")
		v1.PUT("/cert/password", h.UpdateCertPassword)
		logEndpoint(http.MethodPut, "/cert/password")
		v1.DELETE("/cert", h.deleteCert)
		logEndpoint(http.MethodDelete, "/cert")
	}

	return r
}

func (h *handler) pingEET(c *gin.Context) {
	err := h.gatewaySvc.Ping(c)
	var taxAdmin error
	if errors.Is(err, gateway.ErrFSCRConnection) {
		taxAdmin = gateway.ErrFSCRConnection
		_ = c.Error(gateway.ErrFSCRConnection)
	}

	var keyStore error
	if errors.Is(err, gateway.ErrKeystoreUnavailable) {
		keyStore = gateway.ErrKeystoreUnavailable
		_ = c.Error(gateway.ErrKeystoreUnavailable)
	}

	code, resp := pingEETResp(taxAdmin, keyStore)
	c.JSON(code, resp)
}

func (h *handler) sendSale(c *gin.Context) {
	// default request
	dateTime := eet.DateTime(time.Now().Truncate(time.Second))
	req := &SendSaleReq{
		UUIDZpravy:   eet.UUIDType(uuid.New().String()),
		DatOdesl:     dateTime,
		PrvniZaslani: true,
		Overeni:      false,
		DatTrzby:     dateTime,
		Rezim:        0,
	}

	// bind to default
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	odpoved, err := h.gatewaySvc.SendSale(c, req.CertID, []byte(req.CertPassword), sendSaleRequest(req))
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, sendSaleResponse(req, odpoved))
}

func (h *handler) storeCert(c *gin.Context) {
	// default request
	req := &StoreCertReq{
		CertID: uuid.New().String(),
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	err := h.gatewaySvc.StoreCert(c, req.CertID, []byte(req.CertPassword), req.PKCS12Data, req.PKCS12Password)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.CertID))
}

func (h *handler) listCertIDs(c *gin.Context) {
	ids, err := h.gatewaySvc.ListCertIDs(c)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, ListCertIDsResp{CertIDs: ids})
}

func (h *handler) updateCertID(c *gin.Context) {
	// default request
	req := &UpdateCertIDReq{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	err := h.gatewaySvc.UpdateCertID(c, req.CertID, req.NewID)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.NewID))
}

func (h *handler) UpdateCertPassword(c *gin.Context) {
	// default request
	req := &UpdateCertPasswordReq{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	err := h.gatewaySvc.UpdateCertPassword(c, req.CertID, []byte(req.CertPassword), []byte(req.NewPassword))
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.CertID))
}

func (h *handler) deleteCert(c *gin.Context) {
	// default request
	req := &DeleteCertReq{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	err := h.gatewaySvc.DeleteID(c, req.CertID)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.CertID))
}

func logEndpoint(method string, path string) {
	log.Info().
		Str("entity", "HTTP Server").
		Str("action", "opening HTTP endpoint").
		Str("method", method).
		Str("path", path).
		Send()
}
