package wsse_test

import (
	"crypto/rsa"
	"encoding/base64"
	"io/ioutil"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func parseTaxpayerCertificate(t require.TestingT, pfxFile string) *rsa.PrivateKey {
	rawPK, err := ioutil.ReadFile(pfxFile)
	require.NoError(t, err)

	roots, err := ca.PlaygroundRoots()
	require.NoError(t, err)

	caSvc := fscr.NewCAService(roots, nil)
	_, pk, err := caSvc.ParseTaxpayerCertificate(rawPK, "eet")
	require.NoError(t, err)

	return pk
}

func TestCalc(t *testing.T) {
	tests := []struct {
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

	for _, tc := range tests {
		t.Run(tc.xmlFile, func(t *testing.T) {
			raw, err := ioutil.ReadFile(tc.xmlFile)
			require.NoError(t, err)

			envelope := etree.NewDocument()
			err = envelope.ReadFromBytes(raw)
			require.NoError(t, err)

			// get signed info
			signature := envelope.FindElement("./Envelope/Header/Security/Signature")
			signedInfoElem := signature.FindElement("./SignedInfo")
			digestValElem := signedInfoElem.FindElement("./Reference/DigestValue")
			sigValElem := signature.FindElement("./SignatureValue")

			// get body
			body := envelope.FindElement("./Envelope/Body")
			// create namespaces defined outside the scope
			body.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
			body.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")

			// check digest value
			calculatedDigest, err := wsse.CalcDigest(body)
			require.NoError(t, err)
			calculatedDigestB64 := base64.StdEncoding.EncodeToString(calculatedDigest)
			require.Equal(t, digestValElem.Text(), calculatedDigestB64)

			// check signature value
			pk := parseTaxpayerCertificate(t, tc.pfxFile)
			calculatedSignature, err := wsse.CalcSignature(pk, signedInfoElem)
			require.NoError(t, err)
			calculatedSignatureB64 := base64.StdEncoding.EncodeToString(calculatedSignature)
			require.Equal(t, sigValElem.Text(), calculatedSignatureB64)
		})
	}
}
