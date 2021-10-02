package main

// WARNING: This file consists of dev snippets.

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/mfcr"
	"github.com/chutommy/eetgateway/pkg/server"
	"github.com/chutommy/eetgateway/pkg/wsse"
)

func main() {
	// pk and cert
	rawCrt, err := ioutil.ReadFile("data/testdata/EET_CA1_Playground-CZ683555118.crt")
	errCheck(err)
	pbCrt, _ := pem.Decode(rawCrt)
	rawKey, err := ioutil.ReadFile("data/testdata/EET_CA1_Playground-CZ683555118.key")
	errCheck(err)
	pbPK, _ := pem.Decode(rawKey)
	pk, err := x509.ParsePKCS8PrivateKey(pbPK.Bytes)
	errCheck(err)
	crt, err := wsse.ParseCertificate(pbCrt)
	errCheck(err)

	// dep services
	c := mfcr.NewClient(mfcr.PlaygroundURL)
	errCheck(err)
	caSvc := mfcr.NewCAService()
	ks := &ks{
		key: pk.(*rsa.PrivateKey),
		crt: crt,
	}
	gSvc := eet.NewGatewayService(c, caSvc, ks)

	// server
	h := server.NewHandler(gSvc)
	srv := server.NewService(h, ":8080")
	fmt.Println(srv.ListenAndServe())
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}

type ks struct {
	key *rsa.PrivateKey
	crt *x509.Certificate
}

func (ks *ks) Get(string) (*keystore.KeyPair, error) {
	return &keystore.KeyPair{
		Cert: ks.crt,
		Key:  ks.key,
	}, nil
}
