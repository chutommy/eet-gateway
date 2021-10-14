package keystore

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

// KeyPair represents a key pair combination of a private and public key.
type KeyPair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// Service represents a keystore abstraction for a KeyPair management.
type Service interface {
	Store(id string, password []byte, kp *KeyPair) error
	Get(id string, password []byte) (*KeyPair, error)
	Delete(id string, password []byte) error
}

type redisService struct {
	crt []byte
	key []byte
}

var salt = []byte("_eetgateway")

func (r *redisService) Store(id string, password []byte, kp *KeyPair) error {
	panic(errors.New("implement me"))
	/*
		derPrivKey := x509.MarshalPKCS1PrivateKey(kp.Key)
		privPem := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derPrivKey,
		})

		pubPem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: kp.Cert.Raw,
		})

		salted := make([]byte, len(password))
		copy(salted, password)
		salted = append(salted, salt...)
		hash := sha256.Sum256(salted)
		c, err := aes.NewCipher(hash[:])
		if err != nil {
			panic(err)
		}

		gcm, err := cipher.NewGCM(c)
		if err != nil {
			panic(err)
		}

		noncePriv := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, noncePriv); err != nil {
			panic(err)
		}

		noncePub := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, noncePub); err != nil {
			panic(err)
		}

		r.key = gcm.Seal(noncePriv, noncePriv, privPem, nil)
		r.crt = gcm.Seal(noncePub, noncePub, pubPem, nil)

		return nil
	*/
}

func (r *redisService) Get(id string, password []byte) (*KeyPair, error) {
	panic(errors.New("implement me"))
	/*
		salted := make([]byte, len(password))
		copy(salted, password)
		salted = append(salted, salt...)
		hash := sha256.Sum256(salted)
		c, err := aes.NewCipher(hash[:])
		if err != nil {
			panic(err)
		}

		gcm, err := cipher.NewGCM(c)
		if err != nil {
			panic(err)
		}

		nonceSize := gcm.NonceSize()
		if len(r.key) < nonceSize {
			panic(err)
		}
		if len(r.crt) < nonceSize {
			panic(err)
		}

		noncePriv, priv := r.key[:nonceSize], r.key[nonceSize:]
		noncePub, pub := r.crt[:nonceSize], r.crt[nonceSize:]

		privKey, err := gcm.Open(nil, noncePriv, priv, nil)
		if err != nil {
			panic(err)
		}

		pubKey, err := gcm.Open(nil, noncePub, pub, nil)
		if err != nil {
			panic(err)
		}

		privPem, _ := pem.Decode(privKey)
		pubPem, _ := pem.Decode(pubKey)

		pk, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
		if err != nil {
			panic(err)
		}

		crt, err := x509.ParseCertificate(pubPem.Bytes)
		if err != nil {
			panic(err)
		}

		return &KeyPair{
			Cert: crt,
			Key:  pk,
		}, nil
	*/
}

func (r *redisService) Delete(id string, password []byte) error {
	panic(errors.New("implement me"))
}

func NewService() Service {
	return &redisService{}
}
