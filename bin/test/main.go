package main

import (
	"fmt"
	"io/ioutil"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/wsse"
)

func main() {
	p12File, err := ioutil.ReadFile("data/certificates/playground-certs/EET_CA1_Playground-CZ683555118.p12")
	errCheck(err)
	roots, err := ca.PlaygroundRoots()
	errCheck(err)
	crt, pk, err := wsse.ParseTaxpayerCertificate(roots, p12File, "eet")
	errCheck(err)

	ks := keystore.NewService()
	err = ks.Store("", []byte("ahoj"), &keystore.KeyPair{
		Cert: crt,
		Key:  pk,
	})
	errCheck(err)

	kp, err := ks.Get("", []byte("ahoj"))
	errCheck(err)

	fmt.Println(kp.Cert.Issuer.Names)
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}
