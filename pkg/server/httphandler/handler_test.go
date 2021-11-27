package httphandler_test

import (
	"net/http"
	"testing"

	mocks "github.com/chutommy/eetgateway/pkg/mocks/gateway"
	"github.com/chutommy/eetgateway/pkg/server/httphandler"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/suite"
)

const quietMode = true

type HTTPHandlerTestSuite struct {
	suite.Suite
	gSvc    *mocks.Service
	handler http.Handler
}

func (suite *HTTPHandlerTestSuite) SetupSuite() {
	if quietMode {
		log.Logger = zerolog.Nop()
	}

	suite.gSvc = new(mocks.Service)
	suite.handler = httphandler.NewHandler(suite.gSvc).HTTPHandler()
}

func (suite *HTTPHandlerTestSuite) TearDownSuite() {
	suite.gSvc.AssertExpectations(suite.T())
}

func TestHTTPHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(HTTPHandlerTestSuite))
}
