package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *handler) HTTPHandler() http.Handler {
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
		v1.PUT("/certs/:cert_id/password", h.updateCertPassword)
		v1.DELETE("/certs/:cert_id", h.deleteCert)
	}

	return r
}
