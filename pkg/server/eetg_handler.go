package server

import (
	"errors"

	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/gin-gonic/gin"
)

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
