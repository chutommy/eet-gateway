package eet

import (
	"context"
	"errors"
	"fmt"

	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/mfcr"
)

// ErrCertificateRetrieval is returned if a certificate with the given ID couldn't be fetched.
var ErrCertificateRetrieval = errors.New("certificate couldn't be retrieved")

// ErrRequestConstruction is returned if a SOAP request envelope couldn't be built.
var ErrRequestConstruction = errors.New("request couldn't be constructed")

// ErrMFCRConnection is returned if an error occurs during the communication with the MFCR server.
var ErrMFCRConnection = errors.New("MFCR connection error")

// ErrMFCRResponseParse is returned if an error occurs during the MFCR SOAP response parsing.
var ErrMFCRResponseParse = errors.New("SOAP response parse error")

// ErrMFCRResponseVerification is returned if the response doesn't pass security checks and verifications.
var ErrMFCRResponseVerification = errors.New("SOAP response couldn't be successfully verified")

// GatewayService represents an abstraction of EET Gateway functionalities.
type GatewayService interface {
	Send(ctx context.Context, certID string, trzba *TrzbaType) (*OdpovedType, error)
	Ping() error
}

type gatewayService struct {
	mfcrClient mfcr.Client
	caSvc      mfcr.CAService
	keyStore   keystore.Service
	// TODO zap logger
}

// Send sends TrzbaType using mfcr.Client, validate and verifies response and returns OdpovedType.
func (g *gatewayService) Send(ctx context.Context, certID string, trzba *TrzbaType) (*OdpovedType, error) {
	kp, err := g.keyStore.Get(certID)
	if err != nil {
		return nil, fmt.Errorf("keypair from the keystore (id=%s): %v: %w", certID, err, ErrCertificateRetrieval)
	}

	reqEnv, err := newRequestEnvelope(trzba, kp.Cert, kp.Key)
	if err != nil {
		return nil, fmt.Errorf("build a new soap request envelope: %v: %w", err, ErrRequestConstruction)
	}

	respEnv, err := g.mfcrClient.Do(ctx, reqEnv)
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
	if err := g.mfcrClient.Ping(); err != nil {
		return fmt.Errorf("ping MFCR server: %v: %w", err, ErrMFCRConnection)
	}

	return nil
}

// NewGatewayService returns GatewayService implementation.
func NewGatewayService(mfcrClient mfcr.Client, caSvc mfcr.CAService, keyStore keystore.Service) GatewayService {
	return &gatewayService{
		mfcrClient: mfcrClient,
		caSvc:      caSvc,
		keyStore:   keyStore,
	}
}
