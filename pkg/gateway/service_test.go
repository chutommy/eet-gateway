package gateway_test

import (
	"context"
	"testing"

	"github.com/chutommy/eetgateway/pkg/gateway"
	mfscr "github.com/chutommy/eetgateway/pkg/mocks/fscr"
	mkeystore "github.com/chutommy/eetgateway/pkg/mocks/keystore"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestService_PingEET(t *testing.T) {
	tests := []struct {
		name  string
		setup func(c *mfscr.Client, ca *mfscr.CAService, ks *mkeystore.Service)
		errs  []error
	}{
		{
			name: "ok",
			setup: func(c *mfscr.Client, ca *mfscr.CAService, ks *mkeystore.Service) {
				c.On("Ping").Return(nil)
				ks.On("Ping", mock.AnythingOfType("*context.emptyCtx")).Return(nil)
			},
			errs: nil,
		},
		{
			name: "bad fscr",
			setup: func(c *mfscr.Client, ca *mfscr.CAService, ks *mkeystore.Service) {
				c.On("Ping").Return(gateway.ErrFSCRConnection)
				ks.On("Ping", mock.AnythingOfType("*context.emptyCtx")).Return(nil)
			},
			errs: []error{gateway.ErrFSCRConnection},
		},
		{
			name: "bad keystore",
			setup: func(c *mfscr.Client, ca *mfscr.CAService, ks *mkeystore.Service) {
				c.On("Ping").Return(nil)
				ks.On("Ping", mock.AnythingOfType("*context.emptyCtx")).Return(gateway.ErrKeystoreUnavailable)
			},
			errs: []error{gateway.ErrKeystoreUnavailable},
		},
		{
			name: "bad fscr and keystore",
			setup: func(c *mfscr.Client, ca *mfscr.CAService, ks *mkeystore.Service) {
				c.On("Ping").Return(gateway.ErrFSCRConnection)
				ks.On("Ping", mock.AnythingOfType("*context.emptyCtx")).Return(gateway.ErrKeystoreUnavailable)
			},
			errs: []error{gateway.ErrFSCRConnection, gateway.ErrKeystoreUnavailable},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fscrClient := new(mfscr.Client)
			caService := new(mfscr.CAService)
			keystoreService := new(mkeystore.Service)

			tc.setup(fscrClient, caService, keystoreService)

			g := gateway.NewService(fscrClient, caService, keystoreService)
			err := g.Ping(context.Background())
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
