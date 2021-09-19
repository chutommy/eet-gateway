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

	signingContext := &dsig.SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "Id",
		Canonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}
	err = signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod)
	if err != nil {
		return nil, fmt.Errorf("set signature method: %w", err)
	}

	bodyElem := buildBodyElem()
	bodyElem.AddChild(trzbaElem)

	signature, err := signingContext.ConstructSignature(bodyElem, false)
	if err != nil {
		return nil, fmt.Errorf("construct a signature: %w", err)
	}

	env := getEnvelope()
	env.FindElement("./Envelope/Header/Security/BinarySecurityToken").SetText(string(binCrt))
	env.FindElement("./Envelope").AddChild(bodyElem)
	*(env.FindElement("./Envelope/Body")) = *bodyElem
	signatureElem := env.FindElement("./Envelope/Header/Security/Signature")
	signatureElem.FindElement("./SignedInfo/Reference/DigestValue").SetText(signature.FindElement("./SignedInfo/Reference/DigestValue").Text())
	signatureElem.FindElement("./SignatureValue").SetText(signature.FindElement("./SignatureValue").Text())

	signedEnv, err := env.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("parse envelope document to bytes: %w", err)
	}

	return signedEnv, nil
}

var envelopeTmpl *etree.Document

func getEnvelope() *etree.Document {
	if envelopeTmpl == nil {
		envelopeTmpl = buildSOAPEnvelope()
	}

	return envelopeTmpl.Copy()
}

func buildSOAPEnvelope() *etree.Document {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(buildEnvelope())

	return doc
}

func buildEnvelope() *etree.Element {
	envelope := etree.NewElement("Envelope")
	envelope.Space = "s"
	envelope.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	envelope.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
	envelope.AddChild(buildHeader())

	return envelope
}

func buildHeader() *etree.Element {
	header := etree.NewElement("Header")
	header.Space = "s"
	header.AddChild(buildSecurity())

	return header
}

func buildSecurity() *etree.Element {
	security := etree.NewElement("Security")
	security.Space = "wsse"
	security.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	security.AddChild(buildBinarySecurityToken())
	security.AddChild(buildSignature())

	return security
}

func buildBinarySecurityToken() *etree.Element {
	binarySecurityToken := etree.NewElement("BinarySecurityToken")
	binarySecurityToken.Space = "wse"
	binarySecurityToken.CreateAttr("xmlns:wse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	binarySecurityToken.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
	binarySecurityToken.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	binarySecurityToken.CreateAttr("u:Id", "BinaryToken1")

	return binarySecurityToken
}

func buildSignature() *etree.Element {
	signature := etree.NewElement("Signature")
	signature.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	signature.AddChild(buildSignedInfo())
	signature.CreateElement("SignatureValue")
	signature.AddChild(buildKeyInfo())

	return signature
}

func buildSignedInfo() *etree.Element {
	signedInfo := etree.NewElement("SignedInfo")
	signedInfo.CreateElement("CanonicalizationMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	signedInfo.CreateElement("SignatureMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	signedInfo.AddChild(buildReference())

	return signedInfo
}

func buildReference() *etree.Element {
	reference := etree.NewElement("Reference")
	reference.CreateAttr("URI", "#_1")
	reference.CreateElement("Transforms").CreateElement("Transform").CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	reference.CreateElement("DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	reference.CreateElement("DigestValue")

	return reference
}

func buildKeyInfo() *etree.Element {
	keyInfo := etree.NewElement("KeyInfo")
	securityTokenReference := keyInfo.CreateElement("SecurityTokenReference")
	securityTokenReference.Space = "wse"
	securityTokenReference.CreateAttr("xmlns:wse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	tokenReference := securityTokenReference.CreateElement("Reference")
	tokenReference.Space = "wse"
	tokenReference.CreateAttr("URI", "#BinaryToken1")
	tokenReference.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509")

	return keyInfo
}

func buildBodyElem() *etree.Element {
	body := etree.NewElement("Body")
	body.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	body.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
	body.CreateAttr("u:Id", "_1")
	body.Space = "s"

	return body
}
