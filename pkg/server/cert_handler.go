package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

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
	reqURI := &UpdateCertIDURIReq{}
	if err := c.ShouldBindUri(&reqURI); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	reqJSON := &UpdateCertIDJSONReq{}
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

func (h *handler) updateCertPassword(c *gin.Context) {
	reqURI := &UpdateCertPasswordURIReq{}
	if err := c.ShouldBindUri(&reqURI); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	reqJSON := &UpdateCertPasswordJSONReq{}
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
