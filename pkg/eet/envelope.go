package eet

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"text/template"

	"github.com/chutommy/eetgateway/pkg/wsse"
)

// EnvelopeTmplArgument represents an input data for the envelope template.
type EnvelopeTmplArgument struct {
	BinarySecurityToken string
	TrzbaData           string
}

var envelopeTmpl = template.Must(template.New("envelope").Parse(`
<s:Envelope xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Header>
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <wse:BinarySecurityToken xmlns:wse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" u:Id="BinaryToken1">{{.BinarySecurityToken}}</wse:BinarySecurityToken>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <Reference URI="#_1">
                        <Transforms>
                            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        </Transforms>
                        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <DigestValue>digest-value-placeholder</DigestValue>
                    </Reference>
                </SignedInfo>
                <SignatureValue>signature-value-placeholder</SignatureValue>
                <KeyInfo>
                    <wse:SecurityTokenReference xmlns:wse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                        <wse:Reference URI="#BinaryToken1" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509"/>
                    </wse:SecurityTokenReference>
                </KeyInfo>
            </Signature>
        </wsse:Security>
    </s:Header>
    <s:Body u:Id="_1">
        <Trzba xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://fs.mfcr.cz/eet/schema/v3">
{{.TrzbaData}}
        </Trzba>
    </s:Body>
</s:Envelope>
`))

// NewSoapEnvelope a returns a populated and signed SOAP request envelope.
func NewSoapEnvelope(trzbaData []byte, crt *x509.Certificate, pk *rsa.PrivateKey) ([]byte, error) {
	binCrt, err := wsse.CertificateToB64(crt)
	if err != nil {
		return nil, fmt.Errorf("convert certificate to base64: %w", err)
	}

	env, err := buildEnvelope(binCrt, trzbaData)
	if err != nil {
		return nil, fmt.Errorf("build envelope structure: %w", err)
	}

	signedEnv, err := wsse.SignXML(env, pk)
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}

	return signedEnv, nil
}

func buildEnvelope(binaryToken []byte, trzbaData []byte) ([]byte, error) {
	arg := EnvelopeTmplArgument{
		BinarySecurityToken: string(binaryToken),
		TrzbaData:           string(trzbaData),
	}

	buf := &bytes.Buffer{}
	if err := envelopeTmpl.Execute(buf, arg); err != nil {
		return nil, fmt.Errorf("apply envelope template: %w", err)
	}

	return buf.Bytes(), nil
}
