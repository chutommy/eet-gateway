package fscr

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"go.uber.org/multierr"
	"golang.org/x/crypto/pkcs12"
)

// ErrInvalidOrganizationName is returned if the organization name of a certificate is invalid.
var ErrInvalidOrganizationName = errors.New("invalid organization name")

// ErrNotCACertificate is returned if a non-CA's certificate is provided where the one is being expected.
var ErrNotCACertificate = errors.New("not CA's certificate")

// ErrInvalidKeyPair is returned if a certificate/private-key keypair is invalid.
var ErrInvalidKeyPair = errors.New("invalid certificate/private-key keypair")

// ErrInvalidCertificate is returned if a given certificate or private key is invalid.
var ErrInvalidCertificate = errors.New("invalid certificate or private key")

// ErrNotTrustedCertificate is returned if a certificate is issued or signed by an unknown authority
// and can't be trusted.
var ErrNotTrustedCertificate = errors.New("certificate issued or signed by an unknown authority")

// OrganizationName is the legal name that the organization is registered with authority at the national level.
const OrganizationName = "Česká republika - Generální finanční ředitelství"

// CAService verifies certificates signed off by trusted CAs.
type CAService interface {
	VerifyDSig(cert *x509.Certificate) error
	ParseTaxpayerCertificate(data []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error)
}

type caService struct {
	eetCARoots []*x509.Certificate
	dsigPool   *x509.CertPool
}

// NewCAService returns a CAService implementation with the given certificate pools for
// verifying both issued taxpayers' certificates and digital signatures.
func NewCAService(eetRoots []*x509.Certificate, dsigPool *x509.CertPool) CAService {
	return &caService{
		eetCARoots: eetRoots,
		dsigPool:   dsigPool,
	}
}

// VerifyDSig verifies certificate used for the digital signature.
func (c *caService) VerifyDSig(cert *x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots: c.dsigPool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}

	if n := cert.Subject.Organization[0]; n != OrganizationName {
		return fmt.Errorf("unexpected organization name (%s): %w", n, ErrInvalidOrganizationName)
	}

	if _, err := cert.Verify(opts); err != nil {
		return multierr.Append(err, ErrNotTrustedCertificate)
	}

	return nil
}

// ParseTaxpayerCertificate takes a raw data of a PFX file and decodes it into PEM blocks.
// Blocks are expected to be in this order: taxpayer's certificate, certificate authority's certificate
// and private key. CA's certificate is used to verify taxpayer's certificate. The taxpayer's certificate
// and the private key must be a valid keypair.
func (c *caService) ParseTaxpayerCertificate(data []byte, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, nil, fmt.Errorf("convert PFX data to PEM blocks: %w", err)
	}

	cert, caCert, pk, err := parsePEMBlocks(blocks)
	if err != nil {
		return nil, nil, fmt.Errorf("parse PEM blocks: %w", err)
	}

	if err = verifyEETCA(c.eetCARoots, caCert); err != nil {
		return nil, nil, multierr.Append(err, ErrInvalidCertificate)
	}

	err = verifyKeys(caCert, cert, pk)
	if err != nil {
		return nil, nil, multierr.Append(err, ErrInvalidCertificate)
	}

	return cert, pk, nil
}

func parsePEMBlocks(blocks []*pem.Block) (cert *x509.Certificate, caCert *x509.Certificate, pk *rsa.PrivateKey, err error) {
	cert, err = x509.ParseCertificate(blocks[0].Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse taxpayer's certificate: %w", err)
	}

	caCert, err = x509.ParseCertificate(blocks[1].Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse certificate authority's certificate: %w", err)
	}

	pk, err = x509.ParsePKCS1PrivateKey(blocks[2].Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse taxpayer's private key: %w", err)
	}

	return cert, caCert, pk, nil
}

// verifyEETCA verifies a root certificate used for issuing taxpayers' certificates.
func verifyEETCA(roots []*x509.Certificate, cert *x509.Certificate) error {
	var ok bool
	// iterate over stored CA's root certificates
	for _, root := range roots {
		if cert.Equal(root) {
			ok = true
			break
		}
	}

	if !ok {
		return fmt.Errorf("certificate not found in a pool of valid EET CA certificates: %w", ErrNotTrustedCertificate)
	}

	return nil
}

func verifyKeys(caCert *x509.Certificate, cert *x509.Certificate, pk *rsa.PrivateKey) error {
	if isCa := caCert.IsCA; !isCa {
		return fmt.Errorf("expected CA's certificate: %w", ErrNotCACertificate)
	}

	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("taxpayer's certificate not signed off by the CA's certificate: %w", err)
	}

	if !pk.PublicKey.Equal(cert.PublicKey) {
		return fmt.Errorf("the keypair of the taxpayer's private key and the certificate is not valid: %w", ErrInvalidKeyPair)
	}

	return nil
}
