package eet

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/wsse"
)

// NewSoapEnvelope a returns a populated and signed SOAP request envelope.
func NewSoapEnvelope(trzba *TrzbaType, crt *x509.Certificate, pk *rsa.PrivateKey) ([]byte, error) {
	binCrt, err := wsse.CertificateToB64(crt)
	if err != nil {
		return nil, fmt.Errorf("convert certificate to base64: %w", err)
	}

	trzbaElem, err := trzba.Etree()
	if err != nil {
		return nil, fmt.Errorf("marshal trzba to etree.Element: %w", err)
	}

	env := getEnvelope()
	env.FindElement("./Envelope/Header/Security/BinarySecurityToken").SetText(string(binCrt))
	env.FindElement("./Envelope/Body").AddChild(trzbaElem)

	bEnv, err := env.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("parse envelope document to bytes: %w", err)
	}

	signedEnv, err := wsse.SignXML(bEnv, pk)
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}

	return signedEnv, nil
}

var envelopeTmpl *etree.Document

func getEnvelope() *etree.Document {
	if envelopeTmpl == nil {
		envelopeTmpl = buildEnvelope()
	}

	return envelopeTmpl.Copy()
}

func buildEnvelope() *etree.Document {
	doc := etree.NewDocument()

	envelope := doc.CreateElement("Envelope")
	envelope.Space = "s"
	envelope.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	envelope.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")

	header := envelope.CreateElement("Header")
	header.Space = "s"

	security := header.CreateElement("Security")
	security.Space = "wsse"
	security.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")

	binarySecurityToken := security.CreateElement("BinarySecurityToken")
	binarySecurityToken.Space = "wse"
	binarySecurityToken.CreateAttr("xmlns:wse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	binarySecurityToken.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
	binarySecurityToken.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	binarySecurityToken.CreateAttr("u:Id", "BinaryToken1")

	signature := security.CreateElement("Signature")
	signature.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")

	signedInfo := signature.CreateElement("SignedInfo")
	signedInfo.CreateElement("CanonicalizationMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	signedInfo.CreateElement("SignatureMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

	reference := signedInfo.CreateElement("Reference")
	reference.CreateAttr("URI", "#_1")
	reference.CreateElement("Transforms").CreateElement("Transform").CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	reference.CreateElement("DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	reference.CreateElement("DigestValue")

	signature.CreateElement("SignatureValue")

	keyInfo := signature.CreateElement("KeyInfo")
	securityTokenReference := keyInfo.CreateElement("SecurityTokenReference")
	securityTokenReference.Space = "wse"
	securityTokenReference.CreateAttr("xmlns:wse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	tokenReference := securityTokenReference.CreateElement("Reference")
	tokenReference.Space = "wse"
	tokenReference.CreateAttr("URI", "#BinaryToken1")
	tokenReference.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509")

	body := envelope.CreateElement("Body")
	body.Space = "s"
	body.CreateAttr("u:Id", "_1")

	return doc
}
