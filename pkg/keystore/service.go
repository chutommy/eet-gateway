package keystore

import (
	"crypto/rsa"
	"crypto/x509"
)

// KeyPair represents a key pair combination of a private and public key.
type KeyPair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// Service represents a keystore abstraction for a KeyPair management.
type Service interface {
	Get(id string) (*KeyPair, error)
}

// TODO in memory certificate dabase implementation
