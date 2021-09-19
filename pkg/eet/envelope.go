package eet

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/wsse"
)

// NewSoapEnvelope a returns a populated and signed SOAP request envelope.
func NewSoapEnvelope(t *TrzbaType, crt *x509.Certificate, pk *rsa.PrivateKey) ([]byte, error) {
	if err := t.SetSecurityCodes(pk); err != nil {
		return nil, fmt.Errorf("setting security codes: %w", err)
	}

	trzba, err := t.Etree()
	if err != nil {
		return nil, fmt.Errorf("marshal trzba to etree.Element: %w", err)
	}

	binCrt, err := wsse.CertificateToB64(crt)
	if err != nil {
		return nil, fmt.Errorf("convert certificate to base64: %w", err)
	}

	body := buildBodyElem()
	body.AddChild(trzba)
	env := getSoapEnvelope()
	env.FindElement("./Envelope").AddChild(body)
	env.FindElement("./Envelope/Header/Security/BinarySecurityToken").SetText(string(binCrt))
	sig := env.FindElement("./Envelope/Header/Security/Signature")

	if err = setDigestVal(body, sig); err != nil {
		return nil, fmt.Errorf("set digest value: %w", err)
	}

	if err = setSignatureVal(pk, sig); err != nil {
		return nil, fmt.Errorf("set signature value: %w", err)
	}

	signedEnv, err := env.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("parse envelope document to bytes: %w", err)
	}

	return signedEnv, nil
}

func setDigestVal(body *etree.Element, sig *etree.Element) error {
	digest, err := calcDigest(body)
	if err != nil {
		return fmt.Errorf("calculate digest of the body element: %w", err)
	}

	digestVal := base64.StdEncoding.EncodeToString(digest)
	sig.FindElement("./SignedInfo/Reference/DigestValue").SetText(digestVal)

	return nil
}

func setSignatureVal(pk *rsa.PrivateKey, sig *etree.Element) error {
	signedInfo := sig.FindElement("./SignedInfo")
	rawSignature, err := calcSignature(pk, signedInfo.Copy())
	if err != nil {
		return fmt.Errorf("calculate signature value: %w", err)
	}

	signatureVal := base64.StdEncoding.EncodeToString(rawSignature)
	sig.FindElement("./SignatureValue").SetText(signatureVal)

	return nil
}

func calcSignature(pk *rsa.PrivateKey, signedInfo *etree.Element) ([]byte, error) {
	signedInfo.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	detatchedSignedInfo := signedInfo.Copy()

	digest, err := calcDigest(detatchedSignedInfo)
	if err != nil {
		return nil, fmt.Errorf("calculate digest of signed info: %w", err)
	}

	rawSig, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("signing signedInfo digest: %w", err)
	}

	return rawSig, nil
}

func calcDigest(e *etree.Element) ([]byte, error) {
	canonical, err := excC14NCanonicalize(e)
	if err != nil {
		return nil, fmt.Errorf("canonicalize the element (c14n): %w", err)
	}

	hash := crypto.SHA256.New()
	_, err = hash.Write(canonical)
	if err != nil {
		return nil, fmt.Errorf("hash canonicalized element: %w", err)
	}

	return hash.Sum(nil), nil
}
