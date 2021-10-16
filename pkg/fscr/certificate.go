package fscr

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrInvalidOrganizationName is returned if the organization name is invalid.
var ErrInvalidOrganizationName = errors.New("invalid organization name")

// ErrInsecureCertificate is returned if a certificate is signed by an unknown authority and
// can't be verified.
var ErrInsecureCertificate = errors.New("certificate signed by an unknown authority")

// OrganizationName is the legal name that the organization is registered with authority at the national level.
const OrganizationName = "Česká republika - Generální finanční ředitelství"

// EETCAService verifies certificates signed off by the CA.
type EETCAService interface {
	Verify(cert *x509.Certificate) error
}

type eetCAService struct {
	pool *x509.CertPool
}

// Verify verifies cert certificate.
func (c *eetCAService) Verify(cert *x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots: c.pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}

	if n := cert.Subject.Organization[0]; n != OrganizationName {
		return fmt.Errorf("unexpected organization name (%s): %w", n, ErrInvalidOrganizationName)
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("verify certificate: %v: %w", err, ErrInsecureCertificate)
	}

	return nil
}

// NewEETCAService returns a EETCAService implementation with the given certification pool.
func NewEETCAService(pool *x509.CertPool) EETCAService {
	return &eetCAService{
		pool: pool,
	}
}
