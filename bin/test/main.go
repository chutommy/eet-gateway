package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/go-redis/redis/v8"
)

var id = "crt123"
var newid = "crt456"

func main() {
	p12File, err := ioutil.ReadFile("data/certificates/playground-certs/EET_CA1_Playground-CZ683555118.p12")
	errCheck(err)
	roots, err := ca.PlaygroundRoots()
	errCheck(err)
	caSvc := fscr.NewCAService(roots, nil)
	cert, pk, err := caSvc.ParseTaxpayerCertificate(p12File, "eet")
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
		PK:   pk,
	})
	errCheck(err)

	err = ks.UpdatePassword(context.Background(), id, []byte("ahoj"), []byte("nazdar"))
	errCheck(err)

	err = ks.UpdateID(context.Background(), id, newid)
	errCheck(err)

	kp, err := ks.Get(context.Background(), newid, []byte("nazdar"))
	errCheck(err)
	return kp
}

func run2(ks keystore.Service) {
	err := ks.Delete(context.Background(), newid)
	errCheck(err)
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}
