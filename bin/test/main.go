package main

import (
	"io/ioutil"
)

var respEnv = `
<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:eet="http://fs.mfcr.cz/eet/schema/v3" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><wsse:Security soapenv:mustUnderstand="1"><wsse:BinarySecurityToken wsu:Id="SecurityToken-dc64704f-ef9d-4d6d-a4b6-46bcf8ef491d" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">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</wsse:BinarySecurityToken><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
  <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <Reference URI="#Body-d5d8c4bb-9b09-4c0c-b631-46bcf8efa11c">
    <Transforms>
      <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </Transforms>
    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <DigestValue>pMUzL74QJXdjC15P1LCtdxACST+LKDYSpMy0ZqkHKb4=</DigestValue>
  </Reference>
</SignedInfo><SignatureValue>fnYxyAOtgjay82IBBk5aYHXEnRtPX3eV1TtuLsEYsuoJHxB1g6Dn7FN1Dencs8PpW6u9IK50zxrGSUTEbie7kKddOSu4OgB9/6daVPsnmlivdDzh8Xv9FxOpj28OOwZ+iPOx9DevyORYaM1ntPRpkKKnU10dsGipAZCVy4zUnccL0QY+MLAiL7ZXWZFchJooRnEN/SeRA+NHEaWYzptRs1n6LAgW457J/QOPt5noAoj5U1VGIYMPo4Y6GwAGKdzpY9yFV707qOQxwr5jrDUINgRmrV6KKLSf5Df1nWE8+Fc1OpFEPcU9WnxZgQJbRvD2oYcAvL2OC3fqH33qNCQs9w==</SignatureValue><KeyInfo><wsse:SecurityTokenReference xmlns=""><wsse:Reference URI="#SecurityToken-dc64704f-ef9d-4d6d-a4b6-46bcf8ef491d" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/></wsse:SecurityTokenReference></KeyInfo></Signature></wsse:Security></soapenv:Header>

<soapenv:Body wsu:Id="Body-d5d8c4bb-9b09-4c0c-b631-46bcf8efa11c"><eet:Odpoved><eet:Hlavicka uuid_zpravy="e0e80d09-1a19-45da-91d0-56121088ed49" bkp="36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372" dat_prij="2021-09-25T16:17:55+02:00"/><eet:Potvrzeni fik="99bffa84-ace3-4964-9508-46bcf8ef2320-fa" test="true"/></eet:Odpoved></soapenv:Body>

</soapenv:Envelope>
`

func main() {
	// raw, err := ioutil.ReadFile("data/testdata/ppp68.pem")
	// if err != nil {
	// 	panic(err)
	// }
	//
	// pbCrt, rest := pem.Decode(raw)
	// crt, err := wsse.ParseCertificate(pbCrt)
	// if err != nil {
	// 	panic(err)
	// }
	// _ = crt
	//
	// pbCA, rest := pem.Decode(rest)
	// ca, err := wsse.ParseCertificate(pbCA)
	// if err != nil {
	// 	panic(err)
	// }
	// _ = ca
	//
	// pbPk, _ := pem.Decode(rest)
	// pk, err := wsse.ParsePrivateKey(pbPk)
	// if err != nil {
	// 	panic(err)
	// }
	// _ = pk
	//
	// envDoc := etree.NewDocument()
	// err = envDoc.ReadFromString(respEnv)
	// if err != nil {
	// 	panic(err)
	// }
	//
	// bst := envDoc.FindElement("./Envelope/Header/Security/BinarySecurityToken").Text()
	// t, _ := base64.StdEncoding.DecodeString(bst)
	// c, err := x509.ParseCertificate(t)
	// if err != nil {
	// 	panic(err)
	// }
	// _ = c

	raw, err := ioutil.ReadFile("data/testdata/ppp68.pem")
	if err != nil {
		panic(err)
	}

	_ = raw
}
