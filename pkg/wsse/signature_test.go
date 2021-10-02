package wsse_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func TestCalc(t *testing.T) {
	keyPairs := []struct {
		xmlPath string
		pkPath  string
	}{
		{
			xmlPath: "testdata/CZ00000019.v3.valid.v3.1.1.xml",
			pkPath:  "testdata/EET_CA1_Playground-CZ00000019.key",
		},
		{
			xmlPath: "testdata/CZ683555118.v3.valid.v3.1.1.xml",
			pkPath:  "testdata/EET_CA1_Playground-CZ683555118.key",
		},
		{
			xmlPath: "testdata/CZ1212121218.v3.valid.v3.1.1.xml",
			pkPath:  "testdata/EET_CA1_Playground-CZ1212121218.key",
		},
	}

	for _, pkd := range keyPairs {
		t.Run(pkd.xmlPath, func(t *testing.T) {
			xml := readFile(t, pkd.xmlPath)
			key := pkFromFile(t, pkd.pkPath)

			doc := etree.NewDocument()
			err := doc.ReadFromBytes(xml)
			require.NoError(t, err, "retrieve etree from a valid xml value")
			body := doc.FindElement("./Envelope/Body")
			body.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
			body.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
			signature := doc.FindElement("./Envelope/Header/Security/Signature")
			signedInfo := signature.FindElement("./SignedInfo")

			d, err := wsse.CalcDigest(body)
			dv := base64.StdEncoding.EncodeToString(d)
			require.NoError(t, err, "encode digest to base64")
			require.Equal(t, signedInfo.FindElement("./Reference/DigestValue").Text(), dv, "digest values")

			s, err := wsse.CalcSignature(key, signedInfo)
			sv := base64.StdEncoding.EncodeToString(s)
			require.NoError(t, err, "encode signature to base64")
			require.Equal(t, signature.FindElement("./SignatureValue").Text(), sv, "signature values")
		})
	}
}

func pkFromFile(t require.TestingT, path string) *rsa.PrivateKey {
	rawKey := readFile(t, path)
	pbKey, _ := pem.Decode(rawKey)
	key, err := x509.ParsePKCS8PrivateKey(pbKey.Bytes)
	require.NoError(t, err, "parse private key")

	return key.(*rsa.PrivateKey)
}
