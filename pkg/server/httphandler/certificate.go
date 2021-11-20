package httphandler

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) storeCert(c *gin.Context) {
	req := &StoreCertReq{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.PKCS12Data)
	if err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	err = h.gateway.StoreCert(c, req.CertID, []byte(req.CertPassword), data, req.PKCS12Password)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.CertID))
}

func (h *Handler) listCertIDs(c *gin.Context) {
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

	ids, err := h.gateway.ListCertIDs(c, start, end)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, ListCertIDsResp{CertIDs: ids})
}

func (h *Handler) updateCertID(c *gin.Context) {
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

	err := h.gateway.UpdateCertID(c, reqURI.CertID, reqJSON.NewID)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(reqJSON.NewID))
}

func (h *Handler) updateCertPassword(c *gin.Context) {
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

	err := h.gateway.UpdateCertPassword(c, reqURI.CertID, []byte(reqJSON.CertPassword), []byte(reqJSON.NewPassword))
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(reqURI.CertID))
}

func (h *Handler) deleteCert(c *gin.Context) {
	req := &DeleteCertReq{}
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, GatewayErrResp{err.Error()})
		_ = c.Error(err)
		return
	}

	err := h.gateway.DeleteID(c, req.CertID)
	if err != nil {
		code, resp := gatewayErrResp(err)
		c.JSON(code, resp)
		_ = c.Error(err)
		return
	}

	c.JSON(http.StatusOK, successCertResp(req.CertID))
}
