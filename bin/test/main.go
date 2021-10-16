package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/go-redis/redis/v8"
)

var id = "crt123"

func main() {
	p12File, err := ioutil.ReadFile("data/certificates/playground-certs/EET_CA1_Playground-CZ683555118.p12")
	errCheck(err)
	roots, err := ca.PlaygroundRoots()
	errCheck(err)
	cert, pk, err := wsse.ParseTaxpayerCertificate(roots, p12File, "eet")
	errCheck(err)

	rdb := redis.NewClient(&redis.Options{
		Network:      "tcp",
		Addr:         "localhost:6379",
		Username:     "",
		Password:     "",
		DB:           0,
		MinIdleConns: 2,
		TLSConfig:    nil,
	})

	_, err = rdb.Ping(context.Background()).Result()
	errCheck(err)

	ks := keystore.NewRedisService(rdb)

	start := time.Now()
	kp := run(ks, cert, pk)
	fmt.Println(time.Since(start))
	fmt.Println(kp.Cert.Issuer.Names)
	_, _ = cert, pk
	run2(ks)
}

func run(ks keystore.Service, cert *x509.Certificate, pk *rsa.PrivateKey) *keystore.KeyPair {
	err := ks.Store(context.Background(), id, []byte("ahoj"), &keystore.KeyPair{
		Cert: cert,
		Key:  pk,
	})
	errCheck(err)

	kp, err := ks.Get(context.Background(), id, []byte("ahoj"))
	errCheck(err)
	return kp
}

func run2(ks keystore.Service) {
	err := ks.Delete(context.Background(), id)
	errCheck(err)
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}
