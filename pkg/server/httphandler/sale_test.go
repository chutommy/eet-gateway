package httphandler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/chutommy/eetgateway/pkg/server/httphandler"
	"github.com/google/uuid"
	"github.com/sethvargo/go-password/password"
	"github.com/stretchr/testify/mock"
)

func (suite *HTTPHandlerTestSuite) TestSendSale() {
	suite.Run("invalid request", func() { // no request body
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodPost, "/v1/sale", nil, 400)
	})

	suite.Run("unavailable keystore", func() {
		dat := eet.DateTime(time.Now())
		dat.Normalize()
		r := httphandler.SendSaleReq{
			CertID:       uuid.New().String(),
			CertPassword: password.MustGenerate(64, 10, 10, false, false),
			DICPopl:      "CZ683555118",
			IDProvoz:     11,
			IDPokl:       "ABC",
			PoradCis:     "123",
			DatTrzby:     &dat,
			CelkTrzba:    100,
		}

		b, err := json.Marshal(r)
		suite.NoError(err)

		// fix poorly marshalled eet.CastkaType fields
		body := strings.Replace(string(b), "\"100.00\"", "100", 1)
		body = strings.ReplaceAll(body, "\"0.00\"", "0")

		suite.gSvc.On("SendSale", mock.Anything, r.CertID, []byte(r.CertPassword), mock.Anything).
			Return(nil, gateway.ErrKeystoreUnavailable).Once()
		req := httptest.NewRequest(http.MethodPost, "/v1/sale", strings.NewReader(body))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusServiceUnavailable, resp.StatusCode)
	})

	suite.Run("ok", func() {
		dat := eet.DateTime(time.Now().Truncate(time.Second))
		r := httphandler.SendSaleReq{
			CertID:       uuid.New().String(),
			CertPassword: password.MustGenerate(64, 10, 10, false, false),
			UUIDZpravy:   eet.UUIDType(uuid.New().String()),
			DICPopl:      "CZ683555118",
			IDProvoz:     11,
			IDPokl:       "ABC",
			PoradCis:     "123",
			DatTrzby:     &dat,
			CelkTrzba:    100,
			Rezim:        1,
		}

		b, err := json.Marshal(r)
		suite.NoError(err)

		// fix poorly marshalled eet.CastkaType fields
		body := strings.Replace(string(b), "\"100.00\"", "100", 1)
		body = strings.ReplaceAll(body, "\"0.00\"", "0")

		suite.gSvc.On("SendSale", mock.Anything, r.CertID, []byte(r.CertPassword), mock.Anything).
			Return(&eet.OdpovedType{}, nil).Once()
		req := httptest.NewRequest(http.MethodPost, "/v1/sale", strings.NewReader(body))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusOK, resp.StatusCode)
	})
}
