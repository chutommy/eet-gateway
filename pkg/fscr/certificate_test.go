package fscr_test

import (
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/stretchr/testify/require"
)

func TestEETCAService(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		password string
		expErr   error
	}{
		{
			name:     "ok",
			file:     "testdata/response_1.xml",
			password: "eet",
			expErr:   nil,
		},
		{
			name:     "unknown certificate authority",
			file:     "testdata/response_2.xml",
			password: "eet",
			expErr:   fscr.ErrInsecureCertificate,
		},
	}

	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(ca.ICACertificate)
	require.True(t, ok, "ICA certificate is a valid certificate and should be parsable as a PEM block")

	eetCASvc := fscr.NewEETCAService(pool)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// read response file
			resp, err := ioutil.ReadFile(tc.file)
			require.NoError(t, err, "file should exists")

			// load into etree
			doc := etree.NewDocument()
			err = doc.ReadFromBytes(resp)
			require.NoError(t, err, "should be a valid SOAP response")

			// retrieve binary security token
			token := doc.FindElement("./Envelope/Header/Security/BinarySecurityToken")
			require.NotNil(t, token, "response should not miss binary security token")

			// parse to certificate
			tokenB64 := strings.TrimSpace(token.Text())
			certRaw, err := base64.StdEncoding.DecodeString(tokenB64)
			require.NoError(t, err, "binary security token's value is encoded base64")

			cert, err := x509.ParseCertificate(certRaw)
			require.NoError(t, err, "binary security token's value should be a valid x509 certificate")

			// check
			err = eetCASvc.Verify(cert)
			if tc.expErr == nil {
				require.NoError(t, err, "certificate is trusted")
			} else {
				require.Errorf(t, err, "invalid certificate")
				require.ErrorIs(t, err, tc.expErr)
			}
		})
	}
}
