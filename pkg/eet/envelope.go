package eet

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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
	signatureVal, err := calcSignature(ks, bodyElem)
	if err != nil {
		return nil, fmt.Errorf("calculate digest and signature values: %w", err)
	}

	digest, err := calcDigest(bodyElem)
	if err != nil {
		return nil, fmt.Errorf("calculate digest of the body element: %w", err)
	}
	digestVal := base64.StdEncoding.EncodeToString(digest)

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

func calcSignature(ks dsig.X509KeyStore, elem *etree.Element) (signatureVal string, err error) {
	signingCtx := &dsig.SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "Id",
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}
	if err = signingCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return "", fmt.Errorf("set signature method: %w", err)
	}

	s, err := signingCtx.ConstructSignature(elem, false)
	if err != nil {
		return "", fmt.Errorf("construct a signature: %w", err)
	}

	signatureVal = s.FindElementPath(xPathSignatureToSignatureVal).Text()

	return signatureVal, nil
}

func calcDigest(elem *etree.Element) ([]byte, error) {
	canonical, err := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("").Canonicalize(elem)
	if err != nil {
		return nil, fmt.Errorf("canonicalize the element: %w", err)
	}

	hash := crypto.SHA256.New()
	_, err = hash.Write(canonical)
	if err != nil {
		return nil, fmt.Errorf("hash canonicalized element: %w", err)
	}

	return hash.Sum(nil), nil
}
