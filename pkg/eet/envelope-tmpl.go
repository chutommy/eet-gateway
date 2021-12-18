package eet

import "github.com/beevik/etree"

const (
	sXMLNS    = "s"
	wseXMLNS  = "wse"
	wsseXMLNS = "wsse"
)

var envelopeTmpl *etree.Document

func getSoapEnvelope() *etree.Document {
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
	envelope.Space = sXMLNS
	envelope.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	envelope.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
	envelope.AddChild(buildHeader())

	return envelope
}

func buildHeader() *etree.Element {
	header := etree.NewElement("Header")
	header.Space = sXMLNS
	header.AddChild(buildSecurity())

	return header
}

func buildSecurity() *etree.Element {
	security := etree.NewElement("Security")
	security.Space = wsseXMLNS
	security.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	security.AddChild(buildBinarySecurityToken())
	security.AddChild(buildSignature())

	return security
}

func buildBinarySecurityToken() *etree.Element {
	token := etree.NewElement("BinarySecurityToken")
	token.Space = wseXMLNS
	token.CreateAttr("xmlns:wse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	token.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
	token.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
	token.CreateAttr("u:Id", "BinaryToken1")

	return token
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
	securityTokenReference.Space = wseXMLNS
	securityTokenReference.CreateAttr("xmlns:wse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	tokenReference := securityTokenReference.CreateElement("Reference")
	tokenReference.Space = wseXMLNS
	tokenReference.CreateAttr("URI", "#BinaryToken1")
	tokenReference.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509")

	return keyInfo
}

func buildBodyElem() *etree.Element {
	body := etree.NewElement("Body")
	body.CreateAttr("xmlns:u", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	body.CreateAttr("xmlns:s", "http://schemas.xmlsoap.org/soap/envelope/")
	body.CreateAttr("u:Id", "_1")
	body.Space = sXMLNS

	return body
}
