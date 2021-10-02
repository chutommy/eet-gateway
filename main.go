package main

// WARNING: This file consists of dev snippets.

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

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
	certPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            certPool,
				InsecureSkipVerify: false,
			},
		},
	}
	client := mfcr.NewClient(c, mfcr.PlaygroundURL)
	errCheck(err)

	pool, err := x509.SystemCertPool()
	if err != nil {
		panic(fmt.Errorf("system certificate pool: %w", err))
	}
	if ok := pool.AppendCertsFromPEM([]byte(mfcr.ICACertificate)); !ok {
		panic("failed to parse root certificate")
	}
	caSvc := mfcr.NewCAService(pool)

	ks := &ks{
		key: pk.(*rsa.PrivateKey),
		crt: crt,
	}

	gSvc := eet.NewGatewayService(client, caSvc, ks)

	// server
	h := server.NewHandler(gSvc)
	srv := server.NewService(&http.Server{
		Addr:    ":8080",
		Handler: h.Handler(),
		// TLSConfig:         nil,
		ReadTimeout:       time.Second * 10,
		ReadHeaderTimeout: time.Second * 2,
		WriteTimeout:      time.Second * 10,
		IdleTimeout:       time.Second * 100,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
	})
	fmt.Println(srv.ListenAndServe(10 * time.Second))
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
