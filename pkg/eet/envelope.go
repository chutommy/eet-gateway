package eet

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/wsse"
)

// newRequestEnvelope returns a populated and signed SOAP request envelope.
func newRequestEnvelope(t *TrzbaType, crt *x509.Certificate, pk *rsa.PrivateKey) ([]byte, error) {
	if err := t.setSecurityCodes(pk); err != nil {
		return nil, fmt.Errorf("setting security codes: %w", err)
	}

	trzba, err := t.etree()
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
	digest, err := wsse.CalcDigest(body)
	if err != nil {
		return fmt.Errorf("calculate digest of the body element: %w", err)
	}

	digestVal := base64.StdEncoding.EncodeToString(digest)
	sig.FindElement("./SignedInfo/Reference/DigestValue").SetText(digestVal)

	return nil
}

func setSignatureVal(pk *rsa.PrivateKey, sig *etree.Element) error {
	signedInfo := sig.FindElement("./SignedInfo")
	rawSignature, err := wsse.CalcSignature(pk, signedInfo.Copy())
	if err != nil {
		return fmt.Errorf("calculate signature value: %w", err)
	}

	signatureVal := base64.StdEncoding.EncodeToString(rawSignature)
	sig.FindElement("./SignatureValue").SetText(signatureVal)

	return nil
}

// OdpovedBody represents a SOAP Body of the response envelope.
type OdpovedBody struct {
	Odpoved OdpovedType `xml:"Odpoved"`
}

// parseResponseEnvelope returns a parsed SOAP response envelope.
func parseResponseEnvelope(env []byte) (*OdpovedType, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes(env)
	if err != nil {
		return nil, fmt.Errorf("parse envelope to etree: %w", err)
	}

	doc.SetRoot(doc.FindElement("./Envelope/Body"))
	odpovedBytes, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize etree document to bytes: %w", err)
	}

	var odpoved OdpovedBody
	if err = xml.Unmarshal(odpovedBytes, &odpoved); err != nil {
		return nil, fmt.Errorf("decode odpoved bytes: %w", err)
	}

	return &odpoved.Odpoved, nil
}
