package eet

import (
	"bytes"
	"crypto"
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
		return nil, fmt.Errorf("marshal trzba to etree element: %w", err)
	}

	binCrt, err := crtToB64(crt)
	if err != nil {
		return nil, fmt.Errorf("convert certificate to base64: %w", err)
	}

	// build request message
	body := buildBodyElem()
	body.AddChild(trzba)
	env := getSoapEnvelope()
	envElem, err := findElement(env.Root(), ".")
	if err != nil {
		return nil, err
	}
	envElem.AddChild(body)

	tokenElem, err := findElement(envElem, "./Header/Security/BinarySecurityToken")
	if err != nil {
		return nil, err
	}
	tokenElem.SetText(string(binCrt))

	sign, err := findElement(env.Root(), "./Header/Security/Signature")
	if err != nil {
		return nil, err
	}

	if err = setDigestVal(body, sign); err != nil {
		return nil, fmt.Errorf("set digest value: %w", err)
	}

	if err = setSignatureVal(pk, sign); err != nil {
		return nil, fmt.Errorf("set signature value: %w", err)
	}

	signedEnv, err := env.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("parse envelope document to bytes: %w", err)
	}

	return signedEnv, nil
}

func crtToB64(crt *x509.Certificate) ([]byte, error) {
	binary := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, binary)
	if _, err := encoder.Write(crt.Raw); err != nil {
		return nil, fmt.Errorf("encode bytes to binary: %w", err)
	}

	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close binary encoder: %w", err)
	}

	return binary.Bytes(), nil
}

func setDigestVal(body *etree.Element, sign *etree.Element) error {
	digest, err := wsse.CalcDigest(body)
	if err != nil {
		return fmt.Errorf("calculate digest of the body element: %w", err)
	}

	digestVal := base64.StdEncoding.EncodeToString(digest)
	digestValElem, err := findElement(sign, "./SignedInfo/Reference/DigestValue")
	if err != nil {
		return err
	}
	digestValElem.SetText(digestVal)

	return nil
}

func setSignatureVal(pk *rsa.PrivateKey, sign *etree.Element) error {
	signedInfo, err := findElement(sign, "./SignedInfo")
	if err != nil {
		return err
	}

	rawSig, err := wsse.CalcSignature(pk, signedInfo.Copy())
	if err != nil {
		return fmt.Errorf("calculate signature value: %w", err)
	}

	signVal := base64.StdEncoding.EncodeToString(rawSig)
	signValElem, err := findElement(sign, "./SignatureValue")
	if err != nil {
		return err
	}
	signValElem.SetText(signVal)

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
	bodyElem, err := findElement(doc.Root(), "./Body")
	if err != nil {
		return nil, err
	}
	bodyDoc.SetRoot(bodyElem.Copy())

	odpovedBytes, err := bodyDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize etree document to bytes: %w", err)
	}

	var odpoved OdpovedBody
	if err = xml.Unmarshal(odpovedBytes, &odpoved); err != nil {
		return nil, fmt.Errorf("decode odpoved bytes: %w", err)
	}

	return &odpoved.Odpoved, nil
}

func verifyResponse(trzba *TrzbaType, respEnv []byte, odpoved *OdpovedType, verifyCrt func(*x509.Certificate) error) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(respEnv); err != nil {
		return fmt.Errorf("parse envelope to etree: %w", err)
	}

	if !trzba.Hlavicka.Overeni && odpoved.Chyba.Kod == 0 {
		if trzba.KontrolniKody.Bkp.BkpType != odpoved.Hlavicka.Bkp {
			return fmt.Errorf("different bkp: %w", ErrInvalidBKP)
		}

		if err := checkDigSig(doc); err != nil {
			return fmt.Errorf("check digital signature: %w", err)
		}

		if err := verifyCertificate(doc, verifyCrt); err != nil {
			return fmt.Errorf("check certificate: %w", err)
		}
	}

	return nil
}

func verifyCertificate(doc *etree.Document, verifyCrt func(*x509.Certificate) error) error {
	tokenElem := doc.FindElement("./Envelope/Header/Security/BinarySecurityToken")
	if tokenElem == nil {
		return fmt.Errorf("could not find BinarySecurityToken element: %w", ErrInvalidSOAPMessage)
	}

	tokenB64 := tokenElem.Text()
	rawCrt, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return fmt.Errorf("decode binary security token from base64 encoding: %w", err)
	}

	crt, err := x509.ParseCertificate(rawCrt)
	if err != nil {
		return fmt.Errorf("parse raw certificate: %w", err)
	}

	if err = verifyCrt(crt); err != nil {
		return fmt.Errorf("verify security token: %w", err)
	}

	return nil
}

func checkDigSig(doc *etree.Document) error {
	if err := validateDigestValue(doc); err != nil {
		return fmt.Errorf("invalid digest value: %w", err)
	}

	if err := verifySignature(doc); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	return nil
}

func verifySignature(doc *etree.Document) error {
	tokenElem, err := findElement(doc.Root(), "./Header/Security/BinarySecurityToken")
	if err != nil {
		return err
	}
	token := tokenElem.Text()

	rawCrt, _ := base64.StdEncoding.DecodeString(token)
	crt, err := x509.ParseCertificate(rawCrt)
	if err != nil {
		return fmt.Errorf("parse x509 certificate: %w", err)
	}

	sign, err := findElement(doc.Root(), "./Header/Security/Signature")
	if err != nil {
		return err
	}

	signValElem, err := findElement(sign, "./SignatureValue")
	if err != nil {
		return err
	}
	signValB64 := signValElem.Text()

	signVal, err := base64.StdEncoding.DecodeString(signValB64)
	if err != nil {
		return fmt.Errorf("decode base64 signature value: %w", err)
	}

	signedInfo, err := findElement(sign, "./SignedInfo")
	if err != nil {
		return err
	}
	signedInfo.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")

	digest, err := wsse.CalcDigest(signedInfo)
	if err != nil {
		return fmt.Errorf("calculate digest value of signed info: %w", err)
	}

	err = rsa.VerifyPKCS1v15(crt.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest, signVal)
	if err != nil {
		return fmt.Errorf("verify PKCS1v15 signature: %w", err)
	}
	return nil
}

func validateDigestValue(doc *etree.Document) error {
	bodyElem, err := findElement(doc.Root(), "./Body")
	if err != nil {
		return err
	}

	bodyElem.CreateAttr("xmlns:eet", "http://fs.mfcr.cz/eet/schema/v3")
	bodyElem.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	bodyElem.CreateAttr("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	digest, _ := wsse.CalcDigest(bodyElem)
	expDigestVal := base64.StdEncoding.EncodeToString(digest)

	signedInfo, err := findElement(doc.Root(), "./Header/Security/Signature/SignedInfo")
	if err != nil {
		return err
	}

	digestValElem, err := findElement(signedInfo, "./Reference/DigestValue")
	if err != nil {
		return err
	}

	actDigestVal := digestValElem.Text()
	if expDigestVal != actDigestVal {
		return ErrInvalidDigest
	}

	return nil
}

func findElement(root *etree.Element, path string) (*etree.Element, error) {
	e := root.FindElement(path)
	if e == nil {
		return nil, fmt.Errorf("element in %s of %s element not found: %w", path, root.FullTag(), ErrInvalidSOAPMessage)
	}

	return e, nil
}
