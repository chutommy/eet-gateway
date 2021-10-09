package ca_test

import (
	"io/ioutil"
	"testing"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func TestPlaygroundRoots(t *testing.T) {
	tests := []struct {
		file     string
		password string
	}{
		{
			file:     "testdata/EET_CA1_Playground-CZ00000019.p12",
			password: "eet",
		},
		{
			file:     "testdata/EET_CA1_Playground-CZ683555118.p12",
			password: "eet",
		},
		{
			file:     "testdata/EET_CA1_Playground-CZ1212121218.p12",
			password: "eet",
		},
	}

	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			roots, err := ca.PlaygroundRoots()
			require.NoError(t, err, "should be able to retrieve system root certificates")

			raw, err := ioutil.ReadFile(tc.file)
			require.NoError(t, err, "file exists")

			crt, pk, err := wsse.ParseTaxpayerCertificate(roots, raw, tc.password)
			require.NotNilf(t, crt, "valid taxpayer's public key")
			require.NotNilf(t, pk, "valid taxpayer's private key")
			require.NoError(t, err, "valid taxpayer's p12 file")
		})
	}
}
