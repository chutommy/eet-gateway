package wsse_test

import (
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func TestCalc(t *testing.T) {
	keyPairs := []struct {
		xmlFile string
		pfxFile string
	}{
		{
			xmlFile: "testdata/CZ00000019.v3.valid.v3.1.1.xml",
			pfxFile: "testdata/EET_CA1_Playground-CZ00000019.p12",
		},
		{
			xmlFile: "testdata/CZ683555118.v3.valid.v3.1.1.xml",
			pfxFile: "testdata/EET_CA1_Playground-CZ683555118.p12",
		},
		{
			xmlFile: "testdata/CZ1212121218.v3.valid.v3.1.1.xml",
			pfxFile: "testdata/EET_CA1_Playground-CZ1212121218.p12",
		},
	}

	for _, tc := range keyPairs {
		t.Run(tc.xmlFile, func(t *testing.T) {
			xml := readFile(t, tc.xmlFile)

			// load certificate and private key
			rawKey := readFile(t, tc.pfxFile)
			roots, err := ca.PlaygroundRoots()
			require.NoError(t, err, "retrieve playground roots")
			_, key, err := wsse.ParseTaxpayerCertificate(roots, rawKey, "eet")
			require.NoError(t, err, "parse taxpayer's private key")

			doc := etree.NewDocument()
			err = doc.ReadFromBytes(xml)
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
