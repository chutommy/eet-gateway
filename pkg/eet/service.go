package eet

import (
	"context"
	"errors"
	"fmt"

	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/mfcr"
)

var (
	ErrInvalidDigest      = errors.New("reference digest is invalid: computed digest differs from the digest in the XML")
	ErrInvalidBKP         = errors.New("response BKP is invalid")
	ErrInvalidSOAPMessage = errors.New("SOAP message has unexpected structure")
)

// GatewayService represents an abstractioin of EET Gateway functionalities.
type GatewayService interface {
	Send(ctx context.Context, certID string, trzba *TrzbaType) (*OdpovedType, error)
}

type gatewayService struct {
	mfcrClient mfcr.Client
	caSvc      mfcr.CAService
	keyStore   keystore.Service
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

	if err := verifyResponse(trzba, respEnv, odpoved, g.caSvc.Verify); err != nil {
		return nil, fmt.Errorf("verify response: %w", err)
	}

	return odpoved, nil
}

// NewGatewayService returns GatewayService implementation.
func NewGatewayService(mfcrClient mfcr.Client, caSvc mfcr.CAService, keyStore keystore.Service) GatewayService {
	return &gatewayService{
		mfcrClient: mfcrClient,
		caSvc:      caSvc,
		keyStore:   keyStore,
	}
}
