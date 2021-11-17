package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	setValidators()
	r.Use(loggingMiddleware)
	r.Use(recoverMiddleware)

	v1 := r.Group("/v1")
	{
		v1.GET("/ping", h.ping)
		v1.POST("/sale", h.sendSale)
		v1.POST("/certs", h.storeCert)
		v1.GET("/certs", h.listCertIDs)
		v1.PUT("/certs/:cert_id/id", h.updateCertID)
		v1.PUT("/certs/:cert_id/password", h.UpdateCertPassword)
		v1.DELETE("/certs/:cert_id", h.deleteCert)
	}

	return r
}

func (h *handler) ping(c *gin.Context) {
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
	// default request
	req := &ListCertIDsReq{
		Offset: 0,
		Limit:  1000,
	}

	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	start, end := req.Offset, req.Offset+req.Limit-1
	if req.Limit == 0 {
		end = -1
	}

	ids, err := h.gatewaySvc.ListCertIDs(c, start, end)
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
	reqURI := &UpdateCertIDURIReq{}
	reqJSON := &UpdateCertIDJSONReq{}
	if err := c.ShouldBindUri(&reqURI); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}
	if err := c.ShouldBindJSON(&reqJSON); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	err := h.gatewaySvc.UpdateCertID(c, reqURI.CertID, reqJSON.NewID)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(reqJSON.NewID))
}

func (h *handler) UpdateCertPassword(c *gin.Context) {
	// default request
	reqURI := &UpdateCertPasswordURIReq{}
	reqJSON := &UpdateCertPasswordJSONReq{}
	if err := c.ShouldBindUri(&reqURI); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}
	if err := c.ShouldBindJSON(&reqJSON); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	err := h.gatewaySvc.UpdateCertPassword(c, reqURI.CertID, []byte(reqJSON.CertPassword), []byte(reqJSON.NewPassword))
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(reqURI.CertID))
}

func (h *handler) deleteCert(c *gin.Context) {
	// default request
	req := &DeleteCertReq{}
	if err := c.ShouldBindUri(&req); err != nil {
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
