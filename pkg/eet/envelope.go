package eet

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/wsse"
	dsig "github.com/russellhaering/goxmldsig"
)

var (
	xPathToEnvelope              = etree.MustCompilePath("./Envelope")
	xPathToBinSecToken           = etree.MustCompilePath("./Envelope/Header/Security/BinarySecurityToken")
	xPathSignatureToDigestVal    = etree.MustCompilePath("./SignedInfo/Reference/DigestValue")
	xPathSignatureToSignatureVal = etree.MustCompilePath("./SignatureValue")
)

// NewSoapEnvelope a returns a populated and signed SOAP request envelope.
func NewSoapEnvelope(trzba *TrzbaType, ks dsig.X509KeyStore, crt *x509.Certificate, pk *rsa.PrivateKey) ([]byte, error) {
	if err := trzba.SetSecurityCodes(pk); err != nil {
		return nil, fmt.Errorf("setting security codes: %w", err)
	}

	trzbaElem, err := trzba.Etree()
	if err != nil {
		return nil, fmt.Errorf("marshal trzba to etree.Element: %w", err)
	}

	binCrt, err := wsse.CertificateToB64(crt)
	if err != nil {
		return nil, fmt.Errorf("convert certificate to base64: %w", err)
	}

	// singing element
	bodyElem := buildBodyElem()
	bodyElem.AddChild(trzbaElem)
	digestVal, signatureVal, err := calculateSignature(ks, bodyElem)
	if err != nil {
		panic(err)
	}

	// fill envelope
	env := getEnvelope()
	env.FindElementPath(xPathToEnvelope).AddChild(bodyElem)
	env.FindElementPath(xPathToBinSecToken).SetText(string(binCrt))
	signatureElem := env.FindElement("./Envelope/Header/Security/Signature")
	signatureElem.FindElementPath(xPathSignatureToDigestVal).SetText(digestVal)
	signatureElem.FindElementPath(xPathSignatureToSignatureVal).SetText(signatureVal)

	signedEnv, err := env.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("parse envelope document to bytes: %w", err)
	}

	return signedEnv, nil
}

func calculateSignature(ks dsig.X509KeyStore, elem *etree.Element) (digestVal string, signatureVal string, err error) {
	signingCtx := &dsig.SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "Id",
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}
	if err = signingCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return "", "", fmt.Errorf("set signature method: %w", err)
	}

	s, err := signingCtx.ConstructSignature(elem, false)
	if err != nil {
		return "", "", fmt.Errorf("construct a signature: %w", err)
	}

	digestVal = s.FindElementPath(xPathSignatureToDigestVal).Text()
	signatureVal = s.FindElementPath(xPathSignatureToSignatureVal).Text()

	return digestVal, signatureVal, nil
}
