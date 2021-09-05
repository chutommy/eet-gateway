package wsse

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// Certificate represents an X.509 certificate.
type Certificate interface {
	Cert() *x509.Certificate
	Binary() []byte
}

type certificate struct {
	cert   *x509.Certificate
	binary []byte
}

// Cert returns a parsed x509.Certificate.
func (c *certificate) Cert() *x509.Certificate {
	return c.cert
}

// Binary returns the binary encoded certificate.
func (c *certificate) Binary() []byte {
	return c.binary
}

// NewCertificate returns a Certificate instance.
func NewCertificate(der []byte) (Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}

	binary, err := rawToBinary(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("raw to binary: %w", err)
	}

	return &certificate{
		cert:   cert,
		binary: binary,
	}, nil
}

func rawToBinary(raw []byte) ([]byte, error) {
	binary := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.RawStdEncoding, binary)
	if _, err := encoder.Write(raw); err != nil {
		return nil, fmt.Errorf("encode bytes to binary: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close binary encoder: %w", err)
	}

	return binary.Bytes(), nil
}
