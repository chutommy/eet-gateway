package httphandler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// ErrUnexpected is returned if unexpected error is raised.
var ErrUnexpected = errors.New("unexpected error")

// Handler is HTTP requests handler.
type Handler struct {
	gateway gateway.Service
}

// NewHandler returns an implementation of Handler.
func NewHandler(g gateway.Service) *Handler {
	return &Handler{
		gateway: g,
	}
}

// HTTPHandler implements server.Handler.
func (h *Handler) HTTPHandler() http.Handler {
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

func bindingErr(err error) error {
	var verr validator.ValidationErrors
	if errors.As(err, &verr) {
		err = errors.New("invalid request body")
		for _, f := range verr {
			if p := f.Param(); p == "" {
				err = fmt.Errorf("%w %s=%s", err, f.Field(), f.Tag())
			} else {
				err = fmt.Errorf("%w %s=%s(%s)", err, f.Field(), f.Tag(), p)
			}
		}
	}

	return err
}
