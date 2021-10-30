package gateway_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/chutommy/eetgateway/pkg/keystore"
	mfscr "github.com/chutommy/eetgateway/pkg/mocks/fscr"
	mkeystore "github.com/chutommy/eetgateway/pkg/mocks/keystore"
	"github.com/stretchr/testify/require"
)

var errUnexpected = errors.New("unexpected error")

var defaultCertTmpl = &x509.Certificate{
	SerialNumber:          big.NewInt(1),
	NotBefore:             time.Now(),
	NotAfter:              time.Now().Add(time.Minute),
	BasicConstraintsValid: true,
	KeyUsage:              x509.KeyUsageDigitalSignature,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
}

func randomKeyPair() *keystore.KeyPair {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	der, err := x509.CreateCertificate(rand.Reader, defaultCertTmpl, defaultCertTmpl, pk.Public(), pk)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return &keystore.KeyPair{
		Cert: cert,
		PK:   pk,
	}
}

var (
	certID        = "cert1"
	certID2       = "cert2"
	certPassword  = []byte("secret1")
	certPassword2 = []byte("secret2")
	certKP        = randomKeyPair()
	pkcsData      = []byte("p12 data")
	pkcsPassword  = "secret2"
)

func TestService_Ping(t *testing.T) {
	tests := []struct {
		name  string
		setup func(c *mfscr.Client, ks *mkeystore.Service)
		errs  []error
	}{
		{
			name: "ok",
			setup: func(c *mfscr.Client, ks *mkeystore.Service) {
				c.On("Ping").Return(nil)
				ks.On("Ping", context.Background()).Return(nil)
			},
			errs: nil,
		},
		{
			name: "bad fscr",
			setup: func(c *mfscr.Client, ks *mkeystore.Service) {
				c.On("Ping").Return(errUnexpected)
				ks.On("Ping", context.Background()).Return(nil)
			},
			errs: []error{gateway.ErrFSCRConnection},
		},
		{
			name: "bad keystore",
			setup: func(c *mfscr.Client, ks *mkeystore.Service) {
				c.On("Ping").Return(nil)
				ks.On("Ping", context.Background()).Return(errUnexpected)
			},
			errs: []error{gateway.ErrKeystoreUnavailable},
		},
		{
			name: "bad fscr and keystore",
			setup: func(c *mfscr.Client, ks *mkeystore.Service) {
				c.On("Ping").Return(errUnexpected)
				ks.On("Ping", context.Background()).Return(errUnexpected)
			},
			errs: []error{gateway.ErrFSCRConnection, gateway.ErrKeystoreUnavailable},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fscrClient := new(mfscr.Client)
			keystoreService := new(mkeystore.Service)

			tc.setup(fscrClient, keystoreService)

			g := gateway.NewService(fscrClient, new(mfscr.CAService), keystoreService)
			err := g.Ping(context.Background())
			if tc.errs == nil {
				require.NoError(t, err)
			} else {
				for _, e := range tc.errs {
					require.ErrorIs(t, err, e)
				}
			}

			fscrClient.AssertExpectations(t)
			fscrClient.AssertExpectations(t)
			keystoreService.AssertExpectations(t)
		})
	}
}

func TestService_StoreCert(t *testing.T) {
	tests := []struct {
		name  string
		setup func(cas *mfscr.CAService, ks *mkeystore.Service)
		errs  []error
	}{
		{
			name: "ok",
			setup: func(cas *mfscr.CAService, ks *mkeystore.Service) {
				cas.On("ParseTaxpayerCertificate", pkcsData, pkcsPassword).Return(certKP.Cert, certKP.PK, nil)
				ks.On("Store", context.Background(), certID, certPassword, certKP).Return(nil)
			},
			errs: nil,
		},
		{
			name: "invalid certificate",
			setup: func(cas *mfscr.CAService, ks *mkeystore.Service) {
				cas.On("ParseTaxpayerCertificate", pkcsData, pkcsPassword).Return(nil, nil, fscr.ErrInvalidCertificate)
			},
			errs: []error{gateway.ErrInvalidTaxpayersCertificate},
		},
		{
			name: "unknown certificate parse error",
			setup: func(cas *mfscr.CAService, ks *mkeystore.Service) {
				cas.On("ParseTaxpayerCertificate", pkcsData, pkcsPassword).Return(nil, nil, errUnexpected)
			},
			errs: []error{gateway.ErrCertificateParse},
		},
		{
			name: "id already exists",
			setup: func(cas *mfscr.CAService, ks *mkeystore.Service) {
				cas.On("ParseTaxpayerCertificate", pkcsData, pkcsPassword).Return(certKP.Cert, certKP.PK, nil)
				ks.On("Store", context.Background(), certID, certPassword, certKP).Return(keystore.ErrIDAlreadyExists)
			},
			errs: []error{gateway.ErrIDAlreadyExists},
		},
		{
			name: "max tries of db transactions",
			setup: func(cas *mfscr.CAService, ks *mkeystore.Service) {
				cas.On("ParseTaxpayerCertificate", pkcsData, pkcsPassword).Return(certKP.Cert, certKP.PK, nil)
				ks.On("Store", context.Background(), certID, certPassword, certKP).Return(keystore.ErrReachedMaxRetries)
			},
			errs: []error{gateway.ErrTXBlock},
		},
		{
			name: "unknown certificate store error",
			setup: func(cas *mfscr.CAService, ks *mkeystore.Service) {
				cas.On("ParseTaxpayerCertificate", pkcsData, pkcsPassword).Return(certKP.Cert, certKP.PK, nil)
				ks.On("Store", context.Background(), certID, certPassword, certKP).Return(errUnexpected)
			},
			errs: []error{gateway.ErrCertificateStore},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fscrClient := new(mfscr.Client)
			caService := new(mfscr.CAService)
			keystoreService := new(mkeystore.Service)

			tc.setup(caService, keystoreService)

			g := gateway.NewService(fscrClient, caService, keystoreService)
			err := g.StoreCert(context.Background(), certID, certPassword, pkcsData, pkcsPassword)
			if tc.errs == nil {
				require.NoError(t, err)
			} else {
				for _, e := range tc.errs {
					require.ErrorIs(t, err, e)
				}
			}

			fscrClient.AssertExpectations(t)
			caService.AssertExpectations(t)
			keystoreService.AssertExpectations(t)
		})
	}
}

func TestService_ListCertIDs(t *testing.T) {
	tests := []struct {
		name  string
		setup func(ks *mkeystore.Service)
		errs  []error
	}{
		{
			name: "ok",
			setup: func(ks *mkeystore.Service) {
				ks.On("List", context.Background()).Return([]string{certID}, nil)
			},
			errs: nil,
		},
		{
			name: "unknown list certificates error",
			setup: func(ks *mkeystore.Service) {
				ks.On("List", context.Background()).Return(nil, errUnexpected)
			},
			errs: []error{gateway.ErrListCertIDs},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fscrClient := new(mfscr.Client)
			caService := new(mfscr.CAService)
			keystoreService := new(mkeystore.Service)

			tc.setup(keystoreService)

			g := gateway.NewService(fscrClient, caService, keystoreService)
			ids, err := g.ListCertIDs(context.Background())
			if tc.errs == nil {
				require.NoError(t, err)
				require.NotEmpty(t, ids)
			} else {
				for _, e := range tc.errs {
					require.ErrorIs(t, err, e)
				}
			}

			fscrClient.AssertExpectations(t)
			caService.AssertExpectations(t)
			keystoreService.AssertExpectations(t)
		})
	}
}

func TestService_UpdateCertID(t *testing.T) {
	tests := []struct {
		name  string
		setup func(ks *mkeystore.Service)
		errs  []error
	}{
		{
			name: "ok",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdateID", context.Background(), certID, certID2).Return(nil)
			},
			errs: nil,
		},
		{
			name: "certificate not found",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdateID", context.Background(), certID, certID2).Return(keystore.ErrRecordNotFound)
			},
			errs: []error{gateway.ErrCertificateNotFound},
		},
		{
			name: "certificate id already exists",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdateID", context.Background(), certID, certID2).Return(keystore.ErrIDAlreadyExists)
			},
			errs: []error{gateway.ErrIDAlreadyExists},
		},
		{
			name: "max tries of db transactions",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdateID", context.Background(), certID, certID2).Return(keystore.ErrReachedMaxRetries)
			},
			errs: []error{gateway.ErrTXBlock},
		},
		{
			name: "unknown update certificate id error",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdateID", context.Background(), certID, certID2).Return(errUnexpected, errUnexpected)
			},
			errs: []error{gateway.ErrCertificateUpdateID},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fscrClient := new(mfscr.Client)
			caService := new(mfscr.CAService)
			keystoreService := new(mkeystore.Service)

			tc.setup(keystoreService)

			g := gateway.NewService(fscrClient, caService, keystoreService)
			err := g.UpdateCertID(context.Background(), certID, certID2)
			if tc.errs == nil {
				require.NoError(t, err)
			} else {
				for _, e := range tc.errs {
					require.ErrorIs(t, err, e)
				}
			}

			fscrClient.AssertExpectations(t)
			caService.AssertExpectations(t)
			keystoreService.AssertExpectations(t)
		})
	}
}

func TestService_UpdateCertPassword(t *testing.T) {
	tests := []struct {
		name  string
		setup func(ks *mkeystore.Service)
		errs  []error
	}{
		{
			name: "ok",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdatePassword", context.Background(), certID, certPassword, certPassword2).Return(nil)
			},
			errs: nil,
		},
		{
			name: "certificate not found",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdatePassword", context.Background(), certID, certPassword, certPassword2).Return(keystore.ErrRecordNotFound)
			},
			errs: []error{gateway.ErrCertificateNotFound},
		},
		{
			name: "invalid certificate password",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdatePassword", context.Background(), certID, certPassword, certPassword2).Return(keystore.ErrInvalidDecryptionKey)
			},
			errs: []error{gateway.ErrInvalidCertificatePassword},
		},
		{
			name: "max tries of db transactions",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdatePassword", context.Background(), certID, certPassword, certPassword2).Return(keystore.ErrReachedMaxRetries)
			},
			errs: []error{gateway.ErrTXBlock},
		},
		{
			name: "unknown update certificate password error",
			setup: func(ks *mkeystore.Service) {
				ks.On("UpdatePassword", context.Background(), certID, certPassword, certPassword2).Return(errUnexpected)
			},
			errs: []error{gateway.ErrCertificateUpdatePassword},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fscrClient := new(mfscr.Client)
			caService := new(mfscr.CAService)
			keystoreService := new(mkeystore.Service)

			tc.setup(keystoreService)

			g := gateway.NewService(fscrClient, caService, keystoreService)
			err := g.UpdateCertPassword(context.Background(), certID, certPassword, certPassword2)
			if tc.errs == nil {
				require.NoError(t, err)
			} else {
				for _, e := range tc.errs {
					require.ErrorIs(t, err, e)
				}
			}

			fscrClient.AssertExpectations(t)
			caService.AssertExpectations(t)
			keystoreService.AssertExpectations(t)
		})
	}
}

func TestService_DeleteID(t *testing.T) {
	tests := []struct {
		name  string
		setup func(ks *mkeystore.Service)
		errs  []error
	}{
		{
			name: "ok",
			setup: func(ks *mkeystore.Service) {
				ks.On("Delete", context.Background(), certID).Return(nil)
			},
			errs: nil,
		},
		{
			name: "certificate not found",
			setup: func(ks *mkeystore.Service) {
				ks.On("Delete", context.Background(), certID).Return(keystore.ErrRecordNotFound)
			},
			errs: []error{gateway.ErrCertificateNotFound},
		},
		{
			name: "unknown certificate delete error",
			setup: func(ks *mkeystore.Service) {
				ks.On("Delete", context.Background(), certID).Return(errUnexpected)
			},
			errs: []error{gateway.ErrCertificateDelete},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fscrClient := new(mfscr.Client)
			caService := new(mfscr.CAService)
			keystoreService := new(mkeystore.Service)

			tc.setup(keystoreService)

			g := gateway.NewService(fscrClient, caService, keystoreService)
			err := g.DeleteID(context.Background(), certID)
			if tc.errs == nil {
				require.NoError(t, err)
			} else {
				for _, e := range tc.errs {
					require.ErrorIs(t, err, e)
				}
			}

			fscrClient.AssertExpectations(t)
			caService.AssertExpectations(t)
			keystoreService.AssertExpectations(t)
		})
	}
}
