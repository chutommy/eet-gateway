package wsse

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParsePrivateKey parses a PEM encoded RSA private key and returns rsa.PrivateKey.
func ParsePrivateKey(b *pem.Block) (*rsa.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse DER private key: %w", err)
	}

	return pk.(*rsa.PrivateKey), nil
}
