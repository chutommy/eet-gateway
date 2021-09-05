package main

// WARNING: This file consists of dev snippets.

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"golang.org/x/crypto/pkcs12"
)

var t = &eet.TrzbaType{
	Hlavicka: eet.TrzbaHlavickaType{
		Uuidzpravy:   "",
		Datodesl:     eet.DateTime{},
		Prvnizaslani: false,
		Overeni:      false,
	},
	Data: eet.TrzbaDataType{
		Dicpopl:         "",
		Dicpoverujiciho: "",
		Idprovoz:        0,
		Idpokl:          "",
		Poradcis:        "",
		Dattrzby:        eet.DateTime{},
		Celktrzba:       0,
		Zaklnepodldph:   0,
		Zakldan1:        0,
		Dan1:            0,
		Zakldan2:        0,
		Dan2:            0,
		Zakldan3:        0,
		Dan3:            0,
		Cestsluz:        0,
		Pouzitzboz1:     0,
		Pouzitzboz2:     0,
		Pouzitzboz3:     0,
		Urcenocerpzuct:  0,
		Cerpzuct:        0,
		Rezim:           0,
	},
	KontrolniKody: eet.TrzbaKontrolniKodyType{
		Pkp: eet.PkpElementType{
			PkpType:  nil,
			Digest:   "",
			Cipher:   "",
			Encoding: "",
		},
		Bkp: eet.BkpElementType{
			BkpType:  "",
			Digest:   "",
			Encoding: "",
		},
	},
}

func main() {
	rawPK, rawCert := crypto()

	pk, err := x509.ParsePKCS1PrivateKey(rawPK)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := wsse.NewCertificate(rawCert)
	if err != nil {
		log.Fatal(err)
	}

	s, err := t.ContentXML()
	if err != nil {
		log.Fatal(err)
	}

	env, err := eet.NewSoapEnvelope([]byte(s), cert.Binary(), pk)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(env))
	_ = env
}

func crypto() ([]byte, []byte) {
	data, err := ioutil.ReadFile("data/eet-specs/sample-requests/playground-certs/EET_CA1_Playground-CZ00000019.p12")
	if err != nil {
		panic(err)
	}
	pems, err := pkcs12.ToPEM(data, "eet")
	if err != nil {
		panic(err)
	}
	rawPK := pems[2].Bytes
	rawCert := pems[0].Bytes
	return rawPK, rawCert
}
