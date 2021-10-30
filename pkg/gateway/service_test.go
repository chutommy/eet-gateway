package gateway_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chutommy/eetgateway/pkg/gateway"
	mfscr "github.com/chutommy/eetgateway/pkg/mocks/fscr"
	mkeystore "github.com/chutommy/eetgateway/pkg/mocks/keystore"
	"github.com/stretchr/testify/require"
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
				c.On("Ping").Return(errors.New("ping failed"))
				ks.On("Ping", context.Background()).Return(nil)
			},
			errs: []error{gateway.ErrFSCRConnection},
		},
		{
			name: "bad keystore",
			setup: func(c *mfscr.Client, ks *mkeystore.Service) {
				c.On("Ping").Return(nil)
				ks.On("Ping", context.Background()).Return(errors.New("ping failed"))
			},
			errs: []error{gateway.ErrKeystoreUnavailable},
		},
		{
			name: "bad fscr and keystore",
			setup: func(c *mfscr.Client, ks *mkeystore.Service) {
				c.On("Ping").Return(errors.New("ping failed"))
				ks.On("Ping", context.Background()).Return(errors.New("ping failed"))
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
			keystoreService.AssertExpectations(t)
		})
	}
}
