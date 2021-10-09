package main

// WARNING: This file consists of dev snippets.

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/server"
	"github.com/chutommy/eetgateway/pkg/wsse"
)

func main() {
	p12File, err := ioutil.ReadFile("data/certificates/playground-certs/EET_CA1_Playground-CZ683555118.p12")
	errCheck(err)
	roots, err := ca.PlaygroundRoots()
	errCheck(err)
	crt, pk, err := wsse.ParseTaxpayerCertificate(roots, p12File, "eet")
	errCheck(err)

	// dep services
	certPool, err := x509.SystemCertPool()
	errCheck(err)
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            certPool,
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS13,
			},
		},
	}

	client := fscr.NewClient(c, fscr.PlaygroundURL)
	errCheck(err)

	pool, err := x509.SystemCertPool()
	errCheck(err)
	if ok := pool.AppendCertsFromPEM(ca.ICACertificate); !ok {
		panic("failed to parse root certificate")
	}
	eetCASvc := fscr.NewEETCAService(pool)

	ks := &ks{
		key: pk,
		crt: crt,
	}

	gSvc := eet.NewGatewayService(client, eetCASvc, ks)

	// server
	h := server.NewHandler(gSvc)
	srv := server.NewService(&http.Server{
		Addr:    ":8080",
		Handler: h.HTTPHandler(),
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
