package wsse_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func TestSignXML(t *testing.T) {
	keyPairs := []struct {
		pkPath  string
		crtPath string
	}{
		{
			pkPath:  "testdata/EET_CA1_Playground-CZ00000019.key",
			crtPath: "testdata/EET_CA1_Playground-CZ00000019.crt",
		},
		{
			pkPath:  "testdata/EET_CA1_Playground-CZ683555118.key",
			crtPath: "testdata/EET_CA1_Playground-CZ683555118.crt",
		},
		{
			pkPath:  "testdata/EET_CA1_Playground-CZ1212121218.key",
			crtPath: "testdata/EET_CA1_Playground-CZ1212121218.crt",
		},
	}

	xml := readFile(t, "testdata/CZ00000019.v3.valid.v3.1.1-unsigned.xml")

	for _, pkd := range keyPairs {
		t.Run(pkd.pkPath, func(t *testing.T) {
			key := pkFromFile(t, pkd.pkPath)
			crt := crtFromFile(t, pkd.crtPath)

			_, _, _ = xml, key, crt
		})
	}
}

func crtFromFile(t require.TestingT, path string) *x509.Certificate {
	rawCrt := readFile(t, path)
	pbCrt, _ := pem.Decode(rawCrt)
	crt, err := wsse.ParseCertificate(pbCrt)
	require.NoError(t, err, "compose certificate")

	return crt
}

func pkFromFile(t require.TestingT, path string) *rsa.PrivateKey {
	rawKey := readFile(t, path)
	pbKey, _ := pem.Decode(rawKey)
	key, err := x509.ParsePKCS8PrivateKey(pbKey.Bytes)
	require.NoError(t, err, "parse private key")

	return key.(*rsa.PrivateKey)
}
