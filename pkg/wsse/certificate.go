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
func NewCertificate(raw []byte) (Certificate, error) {
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse raw certificate: %w", err)
	}

	return &certificate{
		cert:   cert,
		binary: rawToBinary(cert.Raw),
	}, nil
}

func rawToBinary(raw []byte) []byte {
	binary := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.RawStdEncoding, binary)
	if _, err := encoder.Write(raw); err != nil {
		panic(fmt.Errorf("encode bytes to binary: %w", err))
	}
	if err := encoder.Close(); err != nil {
		panic(fmt.Errorf("close binary encoder: %w", err))
	}

	return binary.Bytes()
}
