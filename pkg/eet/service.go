package eet

import (
	"context"
	"fmt"

	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/mfcr"
)

// GatewayService represents an abstractioin of EET Gateway functionalities.
type GatewayService interface {
	Send(ctx context.Context, certID string, trzba *TrzbaType) (*OdpovedType, error)
}

type gatewayService struct {
	mfcrClient mfcr.Client
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

	return odpoved, nil
}

// NewGatewayService returns GatewayService implementation.
func NewGatewayService(mfcrClient mfcr.Client, keyStore keystore.Service) GatewayService {
	return &gatewayService{
		mfcrClient: mfcrClient,
		keyStore:   keyStore,
	}
}
