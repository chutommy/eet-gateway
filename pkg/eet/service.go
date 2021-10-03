package eet

import (
	"context"
	"errors"
	"fmt"

	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/mfcr"
)

// ErrInvalidDigest is returned if the referenced digest is invalid. Computed digest differs from the digest in the XML
var ErrInvalidDigest = errors.New("invalid referenced digest: computed digest differs from the digest in the XML")

// ErrInvalidBKP is returned if the response BKP code is different.
var ErrInvalidBKP = errors.New("invalid response BKP")

// ErrInvalidSOAPMessage is returned if an invalid or unexpected SOAP message structure is queried.
var ErrInvalidSOAPMessage = errors.New("SOAP message with unexpected structure")

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
		return nil, fmt.Errorf("get keypair from the keystore: %w", err)
	}

	reqEnv, err := newRequestEnvelope(trzba, kp.Cert, kp.Key)
	if err != nil {
		return nil, fmt.Errorf("build a new soap request envelope: %w", err)
	}

	respEnv, err := g.mfcrClient.Do(ctx, reqEnv)
	if err != nil {
		return nil, fmt.Errorf("make soap request to MFCR server: %w", err)
	}

	odpoved, err := parseResponseEnvelope(respEnv)
	if err != nil {
		return nil, fmt.Errorf("parse response envelope: %w", err)
	}

	err = verifyResponse(trzba, respEnv, odpoved, g.caSvc.Verify)
	if err != nil {
		return nil, fmt.Errorf("verify response: %w", err)
	}

	return odpoved, nil
}

// Ping checks whether the MFCR server is online. It returns nil if the response status is OK.
func (g *gatewayService) Ping() error {
	if err := g.mfcrClient.Ping(); err != nil {
		return fmt.Errorf("ping MFCR server: %w", err)
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
