package eet

import (
	"context"
	"errors"
	"fmt"

	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
)

// ErrCertificateRetrieval is returned if a certificate with the given ID couldn't be fetched.
var ErrCertificateRetrieval = errors.New("EET certificate couldn't be retrieved")

// ErrRequestConstruction is returned if a SOAP request envelope couldn't be built.
var ErrRequestConstruction = errors.New("request to EET couldn't be constructed")

// ErrMFCRConnection is returned if an error occurs during the communication with the MFCR server.
var ErrMFCRConnection = errors.New("MFCR connection error")

// ErrMFCRResponseParse is returned if an error occurs during the MFCR SOAP response parsing.
var ErrMFCRResponseParse = errors.New("MFCR response parse error")

// ErrMFCRResponseVerification is returned if the response doesn't pass security checks and verifications.
var ErrMFCRResponseVerification = errors.New("MFCR response couldn't be successfully verified")

// GatewayService represents an abstraction of EET Gateway functionalities.
type GatewayService interface {
	Send(ctx context.Context, certID string, trzba *TrzbaType) (*OdpovedType, error)
	Ping() error
}

type gatewayService struct {
	fscrClient fscr.Client
	caSvc      fscr.CAService
	keyStore   keystore.Service
}

// Send sends TrzbaType using fscr.Client, validate and verifies response and returns OdpovedType.
func (g *gatewayService) Send(ctx context.Context, certID string, trzba *TrzbaType) (*OdpovedType, error) {
	kp, err := g.keyStore.Get(certID)
	if err != nil {
		return nil, fmt.Errorf("keypair from the keystore (id=%s): %v: %w", certID, err, ErrCertificateRetrieval)
	}

	reqEnv, err := newRequestEnvelope(trzba, kp.Cert, kp.Key)
	if err != nil {
		return nil, fmt.Errorf("build a new soap request envelope: %v: %w", err, ErrRequestConstruction)
	}

	respEnv, err := g.fscrClient.Do(ctx, reqEnv)
	if err != nil {
		return nil, fmt.Errorf("make soap request to MFCR server: %v: %w", err, ErrMFCRConnection)
	}

	odpoved, err := parseResponseEnvelope(respEnv)
	if err != nil {
		return nil, fmt.Errorf("parse response envelope: %v: %w", err, ErrMFCRResponseParse)
	}

	err = verifyResponse(trzba, respEnv, odpoved, g.caSvc.Verify)
	if err != nil {
		return odpoved, fmt.Errorf("verify response: %v: %w", err, ErrMFCRResponseVerification)
	}

	return odpoved, nil
}

// Ping checks whether the MFCR server is online. It returns nil if the response status is OK.
func (g *gatewayService) Ping() error {
	if err := g.fscrClient.Ping(); err != nil {
		return fmt.Errorf("ping MFCR server: %v: %w", err, ErrMFCRConnection)
	}

	return nil
}

// NewGatewayService returns GatewayService implementation.
func NewGatewayService(fscrClient fscr.Client, caSvc fscr.CAService, keyStore keystore.Service) GatewayService {
	return &gatewayService{
		fscrClient: fscrClient,
		caSvc:      caSvc,
		keyStore:   keyStore,
	}
}
