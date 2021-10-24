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

func TestCaService_VerifyDSig(t *testing.T) {
	tests := []struct {
		name     string
		p12File  string
		password string
		expErr   error
	}{
		{
			name:     "ok",
			p12File:  "testdata/response_1.xml",
			password: "eet",
			expErr:   nil,
		},
		{
			name:     "unknown certificate authority",
			p12File:  "testdata/response_2.xml",
			password: "eet",
			expErr:   fscr.ErrNotTrustedCertificate,
		},
	}

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.ICACertificate))
	eetCASvc := fscr.NewCAService(nil, pool)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// read response file
			resp, err := ioutil.ReadFile(tc.p12File)
			require.NoError(t, err)

			// load into etree
			doc := etree.NewDocument()
			require.NoError(t, doc.ReadFromBytes(resp))

			// retrieve binary security token
			token := doc.FindElement("./Envelope/Header/Security/BinarySecurityToken")
			tokenB64 := strings.TrimSpace(token.Text())
			certRaw, err := base64.StdEncoding.DecodeString(tokenB64)
			require.NoError(t, err)

			// parse to x509 certificate
			cert, err := x509.ParseCertificate(certRaw)
			require.NoError(t, err)

			// verify
			err = eetCASvc.VerifyDSig(cert)
			if tc.expErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.expErr)
			}
		})
	}
}

func TestParseTaxpayerCertificate(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		password string
		ok       bool
	}{
		{
			name:     "ok CZ00000019",
			file:     "testdata/EET_CA1_Playground-CZ00000019.p12",
			password: "eet",
			ok:       true,
		},
		{
			name:     "ok CZ683555118",
			file:     "testdata/EET_CA1_Playground-CZ683555118.p12",
			password: "eet",
			ok:       true,
		},
		{
			name:     "ok CZ1212121218",
			file:     "testdata/EET_CA1_Playground-CZ1212121218.p12",
			password: "eet",
			ok:       true,
		},
		{
			name:     "invalid CA of the taxpayer's certificate",
			file:     "testdata/EET_CA1_Playground-invalid.p12",
			password: "eet",
			ok:       false,
		},
	}

	roots, err := ca.PlaygroundRoots()
	require.NoError(t, err)
	caSvc := fscr.NewCAService(roots, nil)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ioutil.ReadFile(tc.file)
			require.NoError(t, err)

			cert, pk, err := caSvc.ParseTaxpayerCertificate(data, tc.password)
			if tc.ok {
				require.NoError(t, err)
				require.NotNil(t, cert)
				require.NotNil(t, pk)
			} else {
				require.Error(t, err)
			}
		})
	}
}
