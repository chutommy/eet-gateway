package wsse

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// CertificateData represents an X.509 certificate.
type CertificateData interface {
	Cert() *x509.Certificate
	Binary() []byte
}

type certificateData struct {
	cert   *x509.Certificate
	binary []byte
}

// Cert returns a parsed x509.Certificate.
func (cd *certificateData) Cert() *x509.Certificate {
	return cd.cert
}

// Binary returns the binary encoded certificate.
func (cd *certificateData) Binary() []byte {
	return cd.binary
}

// NewCertificate returns a CertificateData.
func NewCertificate(b *pem.Block) (CertificateData, error) {
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}

	binary, err := rawToBinary(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("raw to binary: %w", err)
	}

	return &certificateData{
		cert:   cert,
		binary: binary,
	}, nil
}

func rawToBinary(raw []byte) ([]byte, error) {
	binary := new(bytes.Buffer)
	encoder := base64.NewEncoder(base64.StdEncoding, binary)
	if _, err := encoder.Write(raw); err != nil {
		return nil, fmt.Errorf("encode bytes to binary: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close binary encoder: %w", err)
	}

	return binary.Bytes(), nil
}
