package wsse

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/chutommy/eetgateway/pkg/mfcr"
	"golang.org/x/crypto/pkcs12"
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

// ParseTaxpayerCertificate takes a raw data of a PFX file and decodes it into PEM blocks.
// Blocks are expected to be in this order: taxpayer's certificate, certificate authority's certificate
// and private key. CA's certificate is used to verify taxpayer's certificate. The taxpayer's certificate
// and the private key must be a valid keypair.
func ParseTaxpayerCertificate(roots []*x509.Certificate, data []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("convert PFX data to PEM blocks: %w", err)
	}

	crt, caCrt, pk, err := parsePEMBlocks(blocks)
	if err != nil {
		return nil, nil, fmt.Errorf("parse PEM blocks: %w", err)
	}

	if err = checkCACert(roots, caCrt); err != nil {
		return nil, nil, fmt.Errorf("check certificate authority's certificate: %w", err)
	}

	err = verifyKeys(caCrt, crt, pk)
	if err != nil {
		return nil, nil, fmt.Errorf("verify keys: %w", err)
	}

	return crt, pk, nil
}

func checkCACert(roots []*x509.Certificate, caCrt *x509.Certificate) error {
	var ok bool
	for _, root := range roots {
		if caCrt.Equal(root) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("certificate not found in a pool of valid CA's certificates: %w", mfcr.ErrNotCACertificate)
	}

	return nil
}

func verifyKeys(caCrt *x509.Certificate, crt *x509.Certificate, pk *rsa.PrivateKey) error {
	if isCa := caCrt.IsCA; !isCa {
		return fmt.Errorf("expected CA's certificate: %w", mfcr.ErrNotCACertificate)
	}

	if err := crt.CheckSignatureFrom(caCrt); err != nil {
		return fmt.Errorf("taxpayer's certificate not signed off by the CA's certificate: %w", err)
	}

	if !pk.PublicKey.Equal(crt.PublicKey) {
		return fmt.Errorf("the keypair of the taxpayer's private key and the certificate is not valid: %w", mfcr.ErrInvalidKeyPair)
	}

	return nil
}

func parsePEMBlocks(blocks []*pem.Block) (crt *x509.Certificate, caCrt *x509.Certificate, pk *rsa.PrivateKey, err error) {
	crt, err = x509.ParseCertificate(blocks[0].Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse taxpayer's certificate: %w", err)
	}

	caCrt, err = x509.ParseCertificate(blocks[1].Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse certificate authority's certificate: %w", err)
	}

	pk, err = x509.ParsePKCS1PrivateKey(blocks[2].Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse taxpayer's private key: %w", err)
	}

	return crt, caCrt, pk, nil
}
