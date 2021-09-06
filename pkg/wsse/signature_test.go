package wsse_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/ma314smith/signedxml"
	"github.com/stretchr/testify/require"
)

type privateKeyData struct {
	filepath        string
	signingCertPath string
}

var pkData = []privateKeyData{
	{
		filepath:        "testdata/EET_CA1_Playground-CZ00000019.key",
		signingCertPath: "testdata/EET_CA1_Playground-CZ00000019.crt",
	},
	{
		filepath:        "testdata/EET_CA1_Playground-CZ683555118.key",
		signingCertPath: "testdata/EET_CA1_Playground-CZ683555118.crt",
	},
	{
		filepath:        "testdata/EET_CA1_Playground-CZ1212121218.key",
		signingCertPath: "testdata/EET_CA1_Playground-CZ1212121218.crt",
	},
}

func TestSignXML(t *testing.T) {
	xml := readFile(t, "testdata/CZ00000019.v3.valid.v3.1.1-unsigned.xml")

	for _, pkd := range pkData {
		t.Run(pkd.filepath, func(t *testing.T) {
			key, err := pkFromFile(t, pkd.filepath)
			crt := crtFromFile(t, pkd.signingCertPath)

			signedXML, err := wsse.SignXML(xml, key)
			require.NoError(t, err, "sign xml with the private key")

			validateXMLDigSig(t, signedXML, crt)
		})
	}
}

func validateXMLDigSig(t *testing.T, xml []byte, crt wsse.Certificate) {
	t.Helper()

	doc := etree.NewDocument()
	err := doc.ReadFromBytes(xml)
	require.NoError(t, err, "parse signed xml")

	doc.CreateElement("X509Certificate")
	doc.SelectElement("X509Certificate").SetText(string(crt.Binary()))
	xmlWithCert, err := doc.WriteToString()
	require.NoError(t, err, "decode etree document to string")

	validator, err := signedxml.NewValidator(xmlWithCert)
	require.NoError(t, err, "new validator from xml")

	validator.SetReferenceIDAttribute("Id")
	_, err = validator.ValidateReferences()
	require.NoError(t, err, "validate digest and signature values")
}

func crtFromFile(t *testing.T, path string) wsse.Certificate {
	t.Helper()

	rawCrt := readFile(t, path)
	pbCrt, _ := pem.Decode(rawCrt)
	crt, err := wsse.NewCertificate(pbCrt)
	require.NoError(t, err, "compose certificate")

	return crt
}

func pkFromFile(t *testing.T, path string) (*rsa.PrivateKey, error) {
	t.Helper()

	rawKey := readFile(t, path)
	pbKey, _ := pem.Decode(rawKey)
	key, err := x509.ParsePKCS8PrivateKey(pbKey.Bytes)
	require.NoError(t, err, "parse private key")

	return key.(*rsa.PrivateKey), err
}
