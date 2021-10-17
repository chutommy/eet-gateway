package eet

import (
	"context"
	"errors"
	"fmt"

	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
)

// ErrCertificateParsing is returned if a certificate couldn't be parsed.
var ErrCertificateParsing = errors.New("EET certificate/parse key couldn't be parsed")

// ErrCertificateNotFound is returned if a certificate with the given ID couldn't be found.
var ErrCertificateNotFound = errors.New("EET certificate couldn't be found")

// ErrCertificateAlreadyExists is returned if a certificate with the given ID already exists.
var ErrCertificateAlreadyExists = errors.New("EET certificate already exists")

// ErrCertificateRetrieval is returned if a certificate with the given ID couldn't be fetched.
var ErrCertificateRetrieval = errors.New("EET certificate couldn't be retrieved")

// ErrCertificateStore is returned if a certificate couldn't be stored.
var ErrCertificateStore = errors.New("EET certificate couldn't be stored")

// ErrInvalidCipherKey is returned if the given password can't open sealed certificate/private key.
var ErrInvalidCipherKey = errors.New("invalid password for cipher decryption")

// ErrRequestConstruction is returned if a SOAP request envelope couldn't be built.
var ErrRequestConstruction = errors.New("request to EET couldn't be constructed")

// ErrMFCRConnection is returned if an error occurs during the communication with the MFCR server.
var ErrMFCRConnection = errors.New("MFCR connection error")

// ErrMFCRResponseParse is returned if an error occurs during the MFCR SOAP response parsing.
var ErrMFCRResponseParse = errors.New("MFCR response parse error")

// ErrMFCRResponseVerification is returned if the response doesn't pass security checks and verifications.
var ErrMFCRResponseVerification = errors.New("MFCR response couldn't be successfully verified")

// ErrInvalidTaxpayerCertificate is returned if an invalid certificate is given.
var ErrInvalidTaxpayerCertiicate = errors.New("invalid taxpayer's certificate")

// GatewayService represents an abstraction of EET Gateway functionalities.
type GatewayService interface {
	Send(ctx context.Context, certID string, pk []byte, trzba *TrzbaType) (*OdpovedType, error)
	Store(ctx context.Context, certID string, password []byte, pkcsData []byte, pkcsPassword string) error
	Ping() error
}

type gatewayService struct {
	fscrClient fscr.Client
	caSvc      fscr.CAService
	keyStore   keystore.Service
}

// Send sends TrzbaType using fscr.Client, validate and verifies response and returns OdpovedType.
func (g *gatewayService) Send(ctx context.Context, certID string, certPassword []byte, trzba *TrzbaType) (*OdpovedType, error) {
	kp, err := g.keyStore.Get(ctx, certID, certPassword)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrRecordNotFound):
			return nil, fmt.Errorf("not found (id=%s): %v: %w", certID, err, ErrCertificateNotFound)
		case errors.Is(err, keystore.ErrInvalidCipherKey):
			return nil, fmt.Errorf("open sealed certificate/private key (id=%s): %v: %w", certID, err, ErrInvalidCipherKey)
		}

		return nil, fmt.Errorf("keypair from the keystore (id=%s): %v: %w", certID, err, ErrCertificateRetrieval)
	}

	reqEnv, err := newRequestEnvelope(trzba, kp.Cert, kp.PK)
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

	err = verifyResponse(trzba, respEnv, odpoved, g.caSvc.VerifyDSig)
	if err != nil {
		return nil, fmt.Errorf("verify response: %v: %w", err, ErrMFCRResponseVerification)
	}

	return odpoved, nil
}

// Store verifies and stores the taxpayer's certificate.
func (g *gatewayService) Store(ctx context.Context, id string, password []byte, pkcsData []byte, pkcsPassword string) error {
	cert, pk, err := g.caSvc.ParseTaxpayerCertificate(pkcsData, pkcsPassword)
	if err != nil {
		if errors.Is(err, fscr.ErrInvalidCertificate) {
			return fmt.Errorf("taxpayer's certificate: %v: %w", err, ErrInvalidTaxpayerCertiicate)
		}

		return fmt.Errorf("parse taxpayer's certificate: %v: %w", err, ErrCertificateParsing)
	}

	err = g.keyStore.Store(ctx, id, password, &keystore.KeyPair{
		Cert: cert,
		PK:   pk,
	})
	if err != nil {
		if errors.Is(err, keystore.ErrIDAlreadyExists) {
			return fmt.Errorf("store certificate: %v: %w", err, ErrCertificateAlreadyExists)
		}

		return fmt.Errorf("store certificate: %v: %w", err, ErrCertificateStore)
	}

	return nil
}

// Ping checks whether the MFCR server is online. It returns nil if the response status is OK.
func (g *gatewayService) Ping() error {
	if err := g.fscrClient.Ping(); err != nil {
		return fmt.Errorf("ping MFCR server: %v: %w", err, ErrMFCRConnection)
	}

	return nil
}

// NewGatewayService returns GatewayService implementation.
func NewGatewayService(fscrClient fscr.Client, eetCASvc fscr.CAService, keyStore keystore.Service) GatewayService {
	return &gatewayService{
		fscrClient: fscrClient,
		caSvc:      eetCASvc,
		keyStore:   keyStore,
	}
}
