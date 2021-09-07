package main

// WARNING: This file consists of dev snippets.

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/wsse"
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
	pbPK, pbCert := crypto()
	pk, err := x509.ParsePKCS8PrivateKey(pbPK.Bytes)
	errCheck(err)
	crt, err := wsse.ParseCertificate(pbCert)
	errCheck(err)
	s, err := t.ContentXML()
	errCheck(err)
	env, err := eet.NewSoapEnvelope(s, crt, pk.(*rsa.PrivateKey))
	errCheck(err)
	fmt.Println(string(env))
}

func crypto() (*pem.Block, *pem.Block) {
	rawCrt, err := ioutil.ReadFile("pkg/wsse/testdata/EET_CA1_Playground-CZ00000019.crt")
	errCheck(err)
	crt, _ := pem.Decode(rawCrt)
	rawKey, err := ioutil.ReadFile("pkg/wsse/testdata/EET_CA1_Playground-CZ00000019.key")
	errCheck(err)
	pk, _ := pem.Decode(rawKey)
	return pk, crt
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}
