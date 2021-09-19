package main

// WARNING: This file consists of dev snippets.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/soap"
	"github.com/chutommy/eetgateway/pkg/wsse"
)

var t = &eet.TrzbaType{
	Hlavicka: eet.TrzbaHlavickaType{
		Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
		Datodesl:     eet.DateTime(mustParseTime("2021-08-11T15:37:52+02:00")),
		Prvnizaslani: true,
		Overeni:      false,
	},
	Data: eet.TrzbaDataType{
		Dicpopl:   "CZ683555118",
		Idprovoz:  141,
		Idpokl:    "1patro-vpravo",
		Poradcis:  "141-18543-05",
		Dattrzby:  eet.DateTime(mustParseTime("2021-08-11T15:36:14+02:00")),
		Celktrzba: 10.00,
		Zakldan1:  100.00,
		Dan1:      21.00,
		Zakldan2:  100.00,
		Dan2:      15.00,
		Rezim:     0,
	},
}

func main() {
	pbPK, pbCert := crypto()
	pk, err := x509.ParsePKCS8PrivateKey(pbPK.Bytes) // ADAPTER
	errCheck(err)
	crt, err := wsse.ParseCertificate(pbCert)
	errCheck(err)
	env, err := eet.NewSoapEnvelope(t, crt, pk.(*rsa.PrivateKey)) // PORT
	errCheck(err)
	c := soap.NewMFCRClient(false)
	// env = []byte(`<s:Envelope xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><wse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" u:Id="BinaryToken1" xmlns:wse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">MIIEmTCCA4GgAwIBAgIFAKCnuv0wDQYJKoZIhvcNAQELBQAwdzESMBAGCgmSJomT8ixkARkWAkNaMUMwQQYDVQQKDDrEjGVza8OhIFJlcHVibGlrYSDigJMgR2VuZXLDoWxuw60gZmluYW7EjW7DrSDFmWVkaXRlbHN0dsOtMRwwGgYDVQQDExNFRVQgQ0EgMSBQbGF5Z3JvdW5kMB4XDTE5MDgwODE5MjM0MloXDTIyMDgwODE5MjM0MlowQzESMBAGCgmSJomT8ixkARkWAkNaMRMwEQYDVQQDEwpDWjAwMDAwMDE5MRgwFgYDVQQNEw9wcmF2bmlja2Egb3NvYmEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDrVmZ6FE2jYqli43/LbXZ1vEG8USMRcC/zbGgk5mAoQQKMtF5PIm5i84pd0cPOSRtduNODc7mwjbPKd5r8p592zNhpei0/XbQcYQ5rpdf0Y84ZNbg9ZmB4nF8YCBy3Gk28YxfW//vIjqvkuQK6InT4l784gtz/iNAV48ZBkgE/jp+MMii1I+y5EyYkQuRZlCJtOTKdPXECnr5OrxrGUtbjmF7bBWLD2LXlspZoUOmh4RFfd9WHH8PmcQfij5aJq6cgIB2YENCBHSA1/HZZEd8vNLv05owb/BOvXj4n86lYJ8tlJVMcorAsrEzVy+XU++78/j9PewL0ft0jETHd0U8DAgMBAAGjggFeMIIBWjAJBgNVHRMEAjAAMB0GA1UdDgQWBBT8zaUMxlfEGXSD/2PZ089ZLGgerTAfBgNVHSMEGDAWgBR8MHaszNaH0ezJH+JwCCzjX94MBzAOBgNVHQ8BAf8EBAMCBsAwYwYDVR0gBFwwWjBYBgpghkgBZQMCATABMEowSAYIKwYBBQUHAgIwPAw6VGVudG8gY2VydGlmaWvDoXQgYnlsIHZ5ZMOhbiBwb3V6ZSBwcm8gdGVzdG92YWPDrSDDusSNZWx5LjCBlwYDVR0fBIGPMIGMMIGJoIGGoIGDhilodHRwOi8vY3JsLmNhMS1wZy5lZXQuY3ovZWV0Y2ExcGcvYWxsLmNybIYqaHR0cDovL2NybDIuY2ExLXBnLmVldC5jei9lZXRjYTFwZy9hbGwuY3JshipodHRwOi8vY3JsMy5jYTEtcGcuZWV0LmN6L2VldGNhMXBnL2FsbC5jcmwwDQYJKoZIhvcNAQELBQADggEBAKVFyv168b/q0X568G+JDvNnz4XVElbJ1r9ro/xv58QP+FD8PJSR5qxN2F7zKGNYTCee0jSo+XY1KEoSkmeoYHXnQpm7+NG7iUYc2OWu0B3hC/wMMhNEDtmsTwqSLjgSk6pZTTRXfvtaHf7zvU8iw1PGFhb9m9bJlOfLwoMeFclOpdfo80pbwRz5t8io/c0lvGodlYj7INHxjlwdwWf3m2mUx4iuKvoAev0ASCdSMDuUWWjYiMT3PEUqeabeM2dn3xccQ2EhgIcCwhQs2MCA/FDLBbiOt63mUJPJHATIFi/31VKtz11/Gc434HHsVYB8U/aammSyIfMp6bNE6LhaFe8=</wse:BinarySecurityToken><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><Reference URI="#_1"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><DigestValue>OX7JTeL80dE6yDHOs6ILGQzitQI7DB5lEhBH7TNcmbo=</DigestValue></Reference></SignedInfo><SignatureValue>hn3LK3tdJrYBpFZto6Lahtei7A2nVR1wbs45IzvXElZIae7m6zTHDiLetPliq+ZuzvlvfA7llZPeAgk5JNBQX/BP/6B2gomDUPBwsB55cwdfZGk58At2D6++DVqYzYC3esPlPxafZ6x7UOSpg5ShxUgBJsC9YOYlTyWD5Jmh0Z3bfeoZBcNkj1gb7DHE6vNoNWysZgf4xwCn80WaYVVTxyge0FW0dIJ8MeRTNeac4oOWF0Z3104Iu48/NEYqB+ZkyGiBBLVBSIdW8rb2NuRQ+Dg/N8zFNYaH03uF6fpmx/1El1mhooS5yYJurioMZUSJAcasoGDnLqFuEyGNaDCR6Q==</SignatureValue><KeyInfo><wse:SecurityTokenReference xmlns:wse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><wse:Reference URI="#BinaryToken1" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509" /></wse:SecurityTokenReference></KeyInfo></Signature></wsse:Security></s:Header><s:Body u:Id="_1"><Trzba xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://fs.mfcr.cz/eet/schema/v3"><Hlavicka uuid_zpravy="878b2e10-c4a5-4f05-8c90-abc181cd6837" dat_odesl="2019-08-11T15:36:25+02:00" prvni_zaslani="true" overeni="false" /><Data dic_popl="CZ00000019" id_provoz="141" id_pokl="1patro-vpravo" porad_cis="141-18543-05" dat_trzby="2019-08-11T15:36:14+02:00" celk_trzba="236.00" zakl_dan1="100.00" dan1="21.00" zakl_dan2="100.00" dan2="15.00" rezim="0" /><KontrolniKody><pkp digest="SHA256" cipher="RSA2048" encoding="base64" xmlns="http://fs.mfcr.cz/eet/schema/v3">LnIZVjGlkdvO55gRP9Wa4k48X0QZrLU5aWsFDpYlwcCC/S8KHuUI0hxxS9pPP/vhuvKhe+a2YoZJ6wZDMSlPs0QDtt5i6D6XhQx/Oj84Azoo8fgSf5R6QOpnpsmw+X75jsUlwzGm4+YLGrhbScjdUdHIBLw2XCJus5cPXAb3aWcab59X2L/zaZ87oJRIQsmERMgPBtT8GIZNEfnX89OL/EMyyxibUC0C97aEokK1Lvvm55xidC9wWoMJJtKjNjScsGg5HpmOe0Zqekovtyvwt5mYVCx/fXa3OTsas2vVMskZKLyaxd7GYkJ5Y9nWCyuD8/pzKWR/8BxApIL601VHaQ==</pkp><bkp digest="SHA1" encoding="base16" xmlns="http://fs.mfcr.cz/eet/schema/v3">ABA7EB19-7AD8D753-60ED57B3-9AC9957E-C192030B</bkp></KontrolniKody></Trzba></s:Body></s:Envelope>`)
	respBody, err := c.Do(context.Background(), env)
	errCheck(err)
	fmt.Println(string(respBody))
	// fmt.Println(string(env))
	_ = respBody
	_ = env
}

func crypto() (*pem.Block, *pem.Block) {
	rawCrt, err := ioutil.ReadFile("pkg/wsse/testdata/EET_CA1_Playground-CZ683555118.crt")
	errCheck(err)
	crt, _ := pem.Decode(rawCrt)
	rawKey, err := ioutil.ReadFile("pkg/wsse/testdata/EET_CA1_Playground-CZ683555118.key")
	errCheck(err)
	pk, _ := pem.Decode(rawKey)
	return pk, crt
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}

func mustParseTime(s string) time.Time {
	t, err := parseTime(s)
	if err != nil {
		panic(err)
	}

	return t
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(eet.DateTimeLayout, s)
	if err != nil {
		return t, fmt.Errorf("invalid time format: %w", err)
	}

	return t, nil
}
