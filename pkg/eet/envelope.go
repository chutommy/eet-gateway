package eet

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/wsse"
)

var (
	ErrInvalidDigest = errors.New("reference digest is invalid: computed digest differs from the digest in the XML")
	ErrInvalidWSSE   = errors.New("invalid WSSE structure")
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

	bodyDoc := etree.NewDocument()
	bodyDoc.SetRoot(doc.FindElement("./Envelope/Body").Copy())
	odpovedBytes, err := bodyDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize etree document to bytes: %w", err)
	}

	var odpoved OdpovedBody
	if err = xml.Unmarshal(odpovedBytes, &odpoved); err != nil {
		return nil, fmt.Errorf("decode odpoved bytes: %w", err)
	}

	if odpoved.Odpoved.Chyba.Kod == 0 {
		if err = checkDigSig(doc); err != nil {
			return nil, fmt.Errorf("check digital signature: %w", err)
		}
	}

	return &odpoved.Odpoved, nil
}

func checkDigSig(doc *etree.Document) error {
	if err := validateDigestValue(doc); err != nil {
		return fmt.Errorf("invalid digest value: %w", err)
	}

	if err := verifySignature(doc); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	// TODO check binary security token certificate

	return nil
}

func verifySignature(doc *etree.Document) error {
	binToken := doc.FindElement("./Envelope/Header/Security/BinarySecurityToken").Text()
	rawCrt, _ := base64.StdEncoding.DecodeString(binToken)
	crt, err := x509.ParseCertificate(rawCrt)
	if err != nil {
		return fmt.Errorf("parse x509 certificate: %w", err)
	}

	signature := doc.FindElement("./Envelope/Header/Security/Signature")
	signatureValB64 := signature.FindElement("./SignatureValue").Text()
	signatureVal, err := base64.StdEncoding.DecodeString(signatureValB64)
	if err != nil {
		return fmt.Errorf("decode base64 signature value: %w", err)
	}

	signedInfo := signature.FindElement("./SignedInfo")
	signedInfo.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	digest, err := wsse.CalcDigest(signedInfo)
	if err != nil {
		return fmt.Errorf("calculate digest value of signed info: %w", err)
	}

	err = rsa.VerifyPKCS1v15(crt.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest, signatureVal)
	if err != nil {
		return fmt.Errorf("verify PKCS1v15 signature: %w", err)
	}
	return nil
}

func validateDigestValue(doc *etree.Document) error {
	bodyElem := doc.FindElement("./Envelope/Body")
	bodyElem.CreateAttr("xmlns:eet", "http://fs.mfcr.cz/eet/schema/v3")
	bodyElem.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	bodyElem.CreateAttr("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	digest, _ := wsse.CalcDigest(bodyElem)
	expDigestVal := base64.StdEncoding.EncodeToString(digest[:])

	signedInfo := doc.FindElement("./Envelope/Header/Security/Signature/SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("find signed info %w", ErrInvalidWSSE)
	}

	digestValElem := signedInfo.FindElement("./Reference/DigestValue")
	if digestValElem == nil {
		return fmt.Errorf("find digest value", ErrInvalidWSSE)
	}

	actDigestVal := digestValElem.Text()
	if expDigestVal != actDigestVal {
		return ErrInvalidDigest
	}

	return nil
}
