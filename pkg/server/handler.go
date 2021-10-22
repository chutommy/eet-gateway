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
		v1.GET("/cert", h.listCertIDs)
		v1.PUT("/cert/id", h.updateCertID)
		v1.PUT("/cert/password", h.UpdateCertPassword)
		v1.DELETE("/cert", h.deleteCert)
	}

	return r
}

func (h *handler) pingEET(c *gin.Context) {
	err := h.gatewaySvc.PingEET(c)
	var taxAdmin error
	if errors.Is(err, eet.ErrFSCRConnection) {
		taxAdmin = eet.ErrFSCRConnection
	}

	var keyStore error
	if errors.Is(err, eet.ErrKeystoreUnavailable) {
		keyStore = eet.ErrKeystoreUnavailable
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
		return
	}

	odpoved, err := h.gatewaySvc.SendSale(c, req.CertID, []byte(req.CertPassword), sendSaleRequest(req))
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
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
		return
	}

	err := h.gatewaySvc.StoreCert(c, req.CertID, []byte(req.CertPassword), req.PKCS12Data, req.PKCS12Password)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.CertID))
}

func (h *handler) listCertIDs(c *gin.Context) {
	ids, err := h.gatewaySvc.ListCertIDs(c)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		return
	}

	c.JSON(http.StatusOK, ListCertIDsResp{CertIDs: ids})
}

func (h *handler) updateCertID(c *gin.Context) {
	// default request
	req := &UpdateCertIDReq{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		return
	}

	err := h.gatewaySvc.UpdateCertID(c, req.CertID, req.NewID)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.NewID))
}

func (h *handler) UpdateCertPassword(c *gin.Context) {
	// default request
	req := &UpdateCertPasswordReq{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		return
	}

	err := h.gatewaySvc.UpdateCertPassword(c, req.CertID, []byte(req.CertPassword), []byte(req.NewPassword))
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.CertID))
}

func (h *handler) deleteCert(c *gin.Context) {
	// default request
	req := &DeleteCertReq{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		return
	}

	err := h.gatewaySvc.DeleteID(c, req.CertID)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.CertID))
}
