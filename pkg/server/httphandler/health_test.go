package httphandler_test

import (
	"net/http"

	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/stretchr/testify/mock"
)

func (suite *HTTPHandlerTestSuite) TestPing() {
	suite.Run("ok", func() {
		suite.gSvc.On("Ping", mock.Anything).Return(nil).Once()
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodGet, "/v1/ping", nil, http.StatusOK)
	})

	suite.Run("fscr unavailable", func() {
		suite.gSvc.On("Ping", mock.Anything).Return(gateway.ErrFSCRConnection).Once()
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodGet, "/v1/ping", nil, http.StatusServiceUnavailable)
	})

	suite.Run("keystore unavailable", func() {
		suite.gSvc.On("Ping", mock.Anything).Return(gateway.ErrKeystoreUnavailable).Once()
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodGet, "/v1/ping", nil, http.StatusServiceUnavailable)
	})
}
