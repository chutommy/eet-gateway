package wsse_test

import (
	"crypto/x509"
	"io/ioutil"
	"testing"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/stretchr/testify/require"
)

func mustParseRoots(rootsFunc func() ([]*x509.Certificate, error)) []*x509.Certificate {
	roots, err := rootsFunc()
	if err != nil {
		panic(err)
	}

	return roots
}

func TestParseTaxpayerCertificate(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		password string
		roots    []*x509.Certificate
		ok       bool
	}{
		{
			name:     "ok CZ00000019",
			file:     "testdata/EET_CA1_Playground-CZ00000019.p12",
			password: "eet",
			roots:    mustParseRoots(ca.PlaygroundRoots),
			ok:       true,
		},
		{
			name:     "ok CZ683555118",
			file:     "testdata/EET_CA1_Playground-CZ683555118.p12",
			password: "eet",
			roots:    mustParseRoots(ca.PlaygroundRoots),
			ok:       true,
		},
		{
			name:     "ok CZ1212121218",
			file:     "testdata/EET_CA1_Playground-CZ1212121218.p12",
			password: "eet",
			roots:    mustParseRoots(ca.PlaygroundRoots),
			ok:       true,
		},
		{
			name:     "invalid CA's certificate",
			file:     "testdata/invalid_CA.p12",
			password: "eet",
			roots:    mustParseRoots(ca.PlaygroundRoots),
			ok:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ioutil.ReadFile(tc.file)
			require.NoError(t, err, "file exists")

			caSvc := fscr.NewCAService(tc.roots, nil)
			cert, pk, err := caSvc.ParseTaxpayerCertificate(data, tc.password)
			if tc.ok {
				require.NotNilf(t, cert, "valid taxpayer's certificate")
				require.NotNilf(t, pk, "valid taxpayer's private key")
				require.NoError(t, err, "valid taxpayer's PKCS 12 file")
			} else {
				require.Error(t, err, "invalid taxpayer's PKCS 12 file")
			}
		})
	}
}
