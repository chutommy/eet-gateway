package wsse

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// ParseCertificate parses a PEM encoded SSL certificate and returns x509.Certificate.
func ParseCertificate(b *pem.Block) (*x509.Certificate, error) {
	crt, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}

	return crt, nil
}

// CertificateToB64 encodes the certificate to base64 binary format.
func CertificateToB64(crt *x509.Certificate) ([]byte, error) {
	binary := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, binary)
	if _, err := encoder.Write(crt.Raw); err != nil {
		return nil, fmt.Errorf("encode bytes to binary: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close binary encoder: %w", err)
	}

	return binary.Bytes(), nil
}

// ParsePrivateKey parses a PEM encoded RSA private key and returns rsa.PrivateKey.
func ParsePrivateKey(b *pem.Block) (*rsa.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse DER private key: %w", err)
	}

	return pk.(*rsa.PrivateKey), nil
}
