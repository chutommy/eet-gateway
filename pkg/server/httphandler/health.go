package httphandler

import (
	"errors"

	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/gin-gonic/gin"
)

// @Summary Ověřit stav EETG API
// @Description Ověří stav API služby EET Gateway, keystore (službu spravující databázi) a spojení se servery správce daně.
// @ID ping
// @Tags API
// @Produce json
// @Success 200 {object} PingEETResp "Všechny EETG komponenty jsou dostupné."
// @Failure 503 {object} PingEETResp "Některé EETG komponeny jsou nedostupné."
// @Router /ping [get]
func (h *Handler) ping(c *gin.Context) {
	err := h.gateway.Ping(c)
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
