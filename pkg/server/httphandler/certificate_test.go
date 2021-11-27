package httphandler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/chutommy/eetgateway/pkg/server/httphandler"
	"github.com/google/uuid"
	"github.com/sethvargo/go-password/password"
	"github.com/stretchr/testify/mock"
)

func (suite *HTTPHandlerTestSuite) TestStoreCert() {
	suite.Run("bad request body", func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/certs", bytes.NewReader(nil))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusBadRequest, resp.StatusCode)
	})

	suite.Run("invalid pkcs12 password", func() {
		r := httphandler.StoreCertReq{
			CertID:         uuid.New().String(),
			CertPassword:   password.MustGenerate(64, 10, 10, false, false),
			PKCS12Data:     "dmFsaWQ=", // = "valid"
			PKCS12Password: "eet",
		}

		body, err := json.Marshal(r)
		suite.NoError(err)

		suite.gSvc.On("StoreCert", mock.Anything, r.CertID, []byte(r.CertPassword), []byte("valid"), "eet").
			Return(gateway.ErrInvalidCertificatePassword).Once()
		req := httptest.NewRequest(http.MethodPost, "/v1/certs", bytes.NewReader(body))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusUnauthorized, resp.StatusCode)
	})

	suite.Run("ok", func() {
		r := httphandler.StoreCertReq{
			CertID:         uuid.New().String(),
			CertPassword:   password.MustGenerate(64, 10, 10, false, false),
			PKCS12Data:     "dmFsaWQ=", // = "valid"
			PKCS12Password: "eet",
		}

		body, err := json.Marshal(r)
		suite.NoError(err)

		suite.gSvc.On("StoreCert", mock.Anything, r.CertID, []byte(r.CertPassword), []byte("valid"), "eet").
			Return(nil).Once()
		req := httptest.NewRequest(http.MethodPost, "/v1/certs", bytes.NewReader(body))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusOK, resp.StatusCode)
	})
}

func (suite *HTTPHandlerTestSuite) TestListCertIDs() {
	suite.Run("invalid limit", func() {
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodGet, "/v1/certs", url.Values{"limit": []string{"-1"}}, http.StatusBadRequest)
	})

	suite.Run("keystore unavailable", func() {
		suite.gSvc.On("ListCertIDs", mock.Anything, int64(0), int64(-1)).Return(nil, gateway.ErrKeystoreUnavailable).Once()
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodGet, "/v1/certs", url.Values{"limit": []string{"0"}}, http.StatusServiceUnavailable)
	})

	suite.Run("ok", func() {
		suite.gSvc.On("ListCertIDs", mock.Anything, int64(100), int64(199)).Return([]string{}, nil).Once()
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodGet, "/v1/certs", url.Values{"limit": []string{"100"}, "offset": []string{"100"}}, http.StatusOK)
	})
}

func (suite *HTTPHandlerTestSuite) TestUpdateCertID() {
	suite.Run("invalid uri", func() {
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodPut, "/v1/certs//id", nil, http.StatusBadRequest)
	})

	suite.Run("invalid request body", func() {
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodPut, fmt.Sprintf("/v1/certs/%s/id", uuid.New().String()), nil, http.StatusBadRequest)
	})

	suite.Run("unavailable keystore", func() {
		id := uuid.New().String()
		r := httphandler.UpdateCertIDJSONReq{
			NewID: uuid.New().String(),
		}

		body, err := json.Marshal(r)
		suite.NoError(err)

		suite.gSvc.On("UpdateCertID", mock.Anything, id, r.NewID).Return(gateway.ErrKeystoreUnavailable).Once()
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v1/certs/%s/id", id), bytes.NewReader(body))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusServiceUnavailable, resp.StatusCode)
	})

	suite.Run("ok", func() {
		id := uuid.New().String()
		r := httphandler.UpdateCertIDJSONReq{
			NewID: uuid.New().String(),
		}

		body, err := json.Marshal(r)
		suite.NoError(err)

		suite.gSvc.On("UpdateCertID", mock.Anything, id, r.NewID).Return(nil).Once()
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v1/certs/%s/id", id), bytes.NewReader(body))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusOK, resp.StatusCode)
	})
}

func (suite *HTTPHandlerTestSuite) TestUpdateCertPassword() {
	suite.Run("invalid uri", func() {
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodPut, "/v1/certs//password", nil, http.StatusBadRequest)
	})

	suite.Run("invalid request body", func() {
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodPut, fmt.Sprintf("/v1/certs/%s/password", uuid.New().String()), nil, http.StatusBadRequest)
	})

	suite.Run("unavailable keystore", func() {
		id := uuid.New().String()
		r := httphandler.UpdateCertPasswordJSONReq{
			CertPassword: password.MustGenerate(64, 10, 10, false, false),
			NewPassword:  password.MustGenerate(64, 10, 10, false, false),
		}

		body, err := json.Marshal(r)
		suite.NoError(err)

		suite.gSvc.On("UpdateCertPassword", mock.Anything, id, []byte(r.CertPassword), []byte(r.NewPassword)).Return(gateway.ErrKeystoreUnavailable).Once()
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v1/certs/%s/password", id), bytes.NewReader(body))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusServiceUnavailable, resp.StatusCode)
	})

	suite.Run("ok", func() {
		id := uuid.New().String()
		r := httphandler.UpdateCertPasswordJSONReq{
			CertPassword: password.MustGenerate(64, 10, 10, false, false),
			NewPassword:  password.MustGenerate(64, 10, 10, false, false),
		}

		body, err := json.Marshal(r)
		suite.NoError(err)

		suite.gSvc.On("UpdateCertPassword", mock.Anything, id, []byte(r.CertPassword), []byte(r.NewPassword)).Return(nil).Once()
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/v1/certs/%s/password", id), bytes.NewReader(body))
		rw := httptest.NewRecorder()
		suite.handler.ServeHTTP(rw, req)

		resp := rw.Result()
		defer func() {
			_ = resp.Body.Close()
		}()

		suite.Equal(http.StatusOK, resp.StatusCode)
	})
}

func (suite *HTTPHandlerTestSuite) TestDeleteCert() {
	suite.Run("unavailable keystore", func() {
		id := uuid.New().String()
		suite.gSvc.On("DeleteID", mock.Anything, id).Return(gateway.ErrKeystoreUnavailable).Once()
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodDelete, fmt.Sprintf("/v1/certs/%s", id), nil, http.StatusServiceUnavailable)
	})

	suite.Run("ok", func() {
		id := uuid.New().String()
		suite.gSvc.On("DeleteID", mock.Anything, id).Return(nil).Once()
		suite.HTTPStatusCode(suite.handler.ServeHTTP, http.MethodDelete, fmt.Sprintf("/v1/certs/%s", id), nil, http.StatusOK)
	})
}
