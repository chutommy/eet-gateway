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
		Datodesl:     eet.DateTime(mustParseTime("2019-08-11T15:37:52+02:00")),
		Prvnizaslani: true,
		Overeni:      false,
	},
	Data: eet.TrzbaDataType{
		Dicpopl:   "CZ683555118",
		Idprovoz:  141,
		Idpokl:    "1patro-vpravo",
		Poradcis:  "141-18543-05",
		Dattrzby:  eet.DateTime(mustParseTime("2019-08-11T15:36:14+02:00")),
		Celktrzba: 236.00,
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
	respBody, err := c.Do(context.Background(), env)
	errCheck(err)
	fmt.Println(string(respBody))
	// fmt.Println(string(env))
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
