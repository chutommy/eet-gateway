package ca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ProductionRoots returns CA EET root certificates for production purposes.
func ProductionRoots() ([]*x509.Certificate, error) {
	blockCrt, _ := pem.Decode(RootCAEET1Production)
	blockCrt2025, _ := pem.Decode(RootCAEET1Production2025)

	crt, err := x509.ParseCertificate(blockCrt.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA EET 1 Production certificate: %w", err)
	}

	crt2025, err := x509.ParseCertificate(blockCrt2025.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA EET 1 Production 2025 certificate: %w", err)
	}

	return []*x509.Certificate{crt, crt2025}, nil
}

// PlaygroundRoots returns CA EET root certificates for development purposes.
func PlaygroundRoots() ([]*x509.Certificate, error) {
	blockCrt, _ := pem.Decode(RootCAEET1Playground)
	blockCrt2025, _ := pem.Decode(RootCAEET1Playground2025)

	crt, err := x509.ParseCertificate(blockCrt.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA EET 1 Playground certificate: %w", err)
	}

	crt2025, err := x509.ParseCertificate(blockCrt2025.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA EET 1 Playground 2025 certificate: %w", err)
	}

	return []*x509.Certificate{crt, crt2025}, nil
}
