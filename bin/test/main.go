package main

import (
	"io/ioutil"
)

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

	// TODO check certificate

	_ = raw
}
