package wsse_test

import (
	"encoding/base64"
	"io/ioutil"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func readFile(t require.TestingT, path string) []byte {
	raw, err := ioutil.ReadFile(path)
	require.NoError(t, err, "read file")

	return raw
}

var calcTests = []struct {
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

func TestCalc(t *testing.T) {
	for _, tc := range calcTests {
		t.Run(tc.xmlFile, func(t *testing.T) {
			xml := readFile(t, tc.xmlFile)

			// load certificate and private key
			rawKey := readFile(t, tc.pfxFile)
			roots, err := ca.PlaygroundRoots()
			require.NoError(t, err, "retrieve playground roots")
			_, key, err := wsse.ParseTaxpayerCertificate(roots, rawKey, "eet")
			require.NoError(t, err, "parse taxpayer's private key")

			envelope := etree.NewDocument()
			err = envelope.ReadFromBytes(xml)
			require.NoError(t, err, "retrieve etree from a valid xml value")

			// get signed info
			body := envelope.FindElement("./Envelope/Body")
			// create namespaces defined outside the scope
			body.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
			body.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
			signature := envelope.FindElement("./Envelope/Header/Security/Signature")

			signedInfoElem := signature.FindElement("./SignedInfo")
			sigValElem := signature.FindElement("./SignatureValue")
			digestValElem := signedInfoElem.FindElement("./Reference/DigestValue")

			calculatedDigest, err := wsse.CalcDigest(body)
			calculatedDigestB64 := base64.StdEncoding.EncodeToString(calculatedDigest)
			require.NoError(t, err, "encode digest to base64")
			require.Equal(t, digestValElem.Text(), calculatedDigestB64, "digest values")

			calculatedSignature, err := wsse.CalcSignature(key, signedInfoElem)
			calculatedSignatureB64 := base64.StdEncoding.EncodeToString(calculatedSignature)
			require.NoError(t, err, "encode signature to base64")
			require.Equal(t, sigValElem.Text(), calculatedSignatureB64, "signature values")
		})
	}
}
