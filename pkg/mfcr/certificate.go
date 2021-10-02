package mfcr

import (
	"crypto/x509"
	"errors"
	"fmt"
)

var ErrInvalidOrganizationName = errors.New("invalid organization name")

const (
	// OrganizationName is the legal name that the organization is registered with authority at the national level.
	OrganizationName = "Česká republika - Generální finanční ředitelství"
)

// CAService verifies certificates signed off by the CA.
type CAService interface {
	Verify(crt *x509.Certificate) error
}

type caService struct {
	pool *x509.CertPool
}

// Verify verifies crt certificate.
func (c *caService) Verify(crt *x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots: c.pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}

	if n := crt.Subject.Organization[0]; n != OrganizationName {
		return fmt.Errorf("%s: %w", n, ErrInvalidOrganizationName)
	}

	if _, err := crt.Verify(opts); err != nil {
		return fmt.Errorf("verify certificate: %w", err)
	}

	return nil
}

// NewCAService returns a CAService implementation with the given certification pool.
func NewCAService(pool *x509.CertPool) CAService {
	return &caService{
		pool: pool,
	}
}
