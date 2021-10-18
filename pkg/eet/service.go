package eet

import (
	"context"
	"errors"
	"fmt"

	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
)

// ErrCertificateNotFound is returned if a certificate with the given ID can't be found.
var ErrCertificateNotFound = errors.New("taxpayer's certificate can't be found")

// ErrIDAlreadyExists is returned if a certificate with the given ID already exists.
var ErrIDAlreadyExists = errors.New("taxpayer's certificate with the ID already exists")

// ErrCertificateParse is returned if a certificate can't be parsed.
var ErrCertificateParse = errors.New("taxpayer's certificate can't be parsed")

// ErrCertificateGet is returned if a certificate with the given ID can't be fetched.
var ErrCertificateGet = errors.New("taxpayer's certificate can't be retrieved")

// ErrCertificateStore is returned if a certificate can't be stored.
var ErrCertificateStore = errors.New("taxpayer's certificate can't be stored")

// ErrCertificateUpdatePassword is returned if password of a certificate can't be updated.
var ErrCertificateUpdatePassword = errors.New("password to the taxpayer's certificate can't be updated")

// ErrCertificatUpdateID is returned if id of a certificate can't be updated.
var ErrCertificatUpdateID = errors.New("id of the taxpayer's certificate can't be updated")

// ErrCertificateDelete is returned if a certificate can't be deleted.
var ErrCertificateDelete = errors.New("taxpayer's certificate can't be deleted")

// ErrInvalidCertificatePassword is returned if the given password can't open sealed certificate/private key.
var ErrInvalidCertificatePassword = errors.New("invalid password for the decryption of the taxpayer's certificate")

// ErrRequestBuild is returned if a SOAP request envelope can't be built.
var ErrRequestBuild = errors.New("request to FSCR can't be constructed")

// ErrFSCRConnection is returned if an error occurs during the communication with the MFCR server.
var ErrFSCRConnection = errors.New("FSCR connection error")

// ErrFSCRResponseParse is returned if an error occurs during the MFCR SOAP response parsing.
var ErrFSCRResponseParse = errors.New("FSCR response parse error")

// ErrFSCRResponseVerify is returned if the response doesn't pass security checks and verifications.
var ErrFSCRResponseVerify = errors.New("FSCR response can't be successfully verified")

// ErrInvalidTaxpayersCertificate is returned if an invalid certificate is given.
var ErrInvalidTaxpayersCertificate = errors.New("invalid taxpayer's certificate")

// GatewayService represents an abstraction of EET Gateway functionalities.
type GatewayService interface {
	PingEET() error
	SendSale(ctx context.Context, certID string, pk []byte, trzba *TrzbaType) (*OdpovedType, error)
	StoreCert(ctx context.Context, certID string, password []byte, pkcsData []byte, pkcsPassword string) error
	UpdateCertPassword(ctx context.Context, id string, oldPassword, newPassword []byte) error
	UpdateCertID(ctx context.Context, oldID, newID string) error
	DeleteID(ctx context.Context, id string) error
}

type gatewayService struct {
	fscrClient fscr.Client
	caSvc      fscr.CAService
	keyStore   keystore.Service
}

// Send sends TrzbaType using fscr.Client, validate and verifies response and returns OdpovedType.
func (g *gatewayService) SendSale(ctx context.Context, certID string, certPassword []byte, trzba *TrzbaType) (*OdpovedType, error) {
	kp, err := g.keyStore.Get(ctx, certID, certPassword)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrRecordNotFound):
			return nil, fmt.Errorf("not found (id=%s): %v: %w", certID, err, ErrCertificateNotFound)
		case errors.Is(err, keystore.ErrInvalidDecryptionKey):
			return nil, fmt.Errorf("open sealed certificate/private key (id=%s): %v: %w", certID, err, ErrInvalidCertificatePassword)
		}

		return nil, fmt.Errorf("keypair from the keystore (id=%s): %v: %w", certID, err, ErrCertificateGet)
	}

	reqEnv, err := newRequestEnvelope(trzba, kp.Cert, kp.PK)
	if err != nil {
		return nil, fmt.Errorf("build a new soap request envelope: %v: %w", err, ErrRequestBuild)
	}

	respEnv, err := g.fscrClient.Do(ctx, reqEnv)
	if err != nil {
		return nil, fmt.Errorf("make soap request to MFCR server: %v: %w", err, ErrFSCRConnection)
	}

	odpoved, err := parseResponseEnvelope(respEnv)
	if err != nil {
		return nil, fmt.Errorf("parse response envelope: %v: %w", err, ErrFSCRResponseParse)
	}

	err = verifyResponse(trzba, respEnv, odpoved, g.caSvc.VerifyDSig)
	if err != nil {
		return nil, fmt.Errorf("verify response: %v: %w", err, ErrFSCRResponseVerify)
	}

	return odpoved, nil
}

// Store verifies and stores the taxpayer's certificate.
func (g *gatewayService) StoreCert(ctx context.Context, id string, password []byte, pkcsData []byte, pkcsPassword string) error {
	cert, pk, err := g.caSvc.ParseTaxpayerCertificate(pkcsData, pkcsPassword)
	if err != nil {
		if errors.Is(err, fscr.ErrInvalidCertificate) {
			return fmt.Errorf("taxpayer's certificate: %v: %w", err, ErrInvalidTaxpayersCertificate)
		}

		return fmt.Errorf("parse taxpayer's certificate: %v: %w", err, ErrCertificateParse)
	}

	err = g.keyStore.Store(ctx, id, password, &keystore.KeyPair{
		Cert: cert,
		PK:   pk,
	})
	if err != nil {
		if errors.Is(err, keystore.ErrIDAlreadyExists) {
			return fmt.Errorf("store certificate: %v: %w", err, ErrIDAlreadyExists)
		}

		return fmt.Errorf("store certificate: %v: %w", err, ErrCertificateStore)
	}

	return nil
}

// UpdatePassword updates the certificate of given ID with a new password.
func (g *gatewayService) UpdateCertPassword(ctx context.Context, id string, oldPassword, newPassword []byte) error {
	err := g.keyStore.UpdatePassword(ctx, id, oldPassword, newPassword)
	if err != nil {
		if errors.Is(err, keystore.ErrRecordNotFound) {
			return fmt.Errorf("find certificate: %w", ErrCertificateNotFound)
		} else if errors.Is(err, keystore.ErrInvalidDecryptionKey) {
			return fmt.Errorf("decrypt certificate with an old key: %w", ErrInvalidCertificatePassword)
		}

		return fmt.Errorf("change password to taxpayer's certificate: %v: %w", err, ErrCertificateUpdatePassword)
	}

	return nil
}

// UpdateID renames the current certificate ID to a new ID.
func (g *gatewayService) UpdateCertID(ctx context.Context, oldID, newID string) error {
	err := g.keyStore.UpdateID(ctx, oldID, newID)
	if err != nil {
		if errors.Is(err, keystore.ErrRecordNotFound) {
			return fmt.Errorf("delete certificate: %v: %w", err, ErrCertificateNotFound)
		} else if errors.Is(err, keystore.ErrIDAlreadyExists) {
			return fmt.Errorf("rename certificate id: %v: %w", err, ErrIDAlreadyExists)
		}

		return fmt.Errorf("rename certificate id: %v: %w", err, ErrCertificatUpdateID)
	}

	return nil
}

// Delete removes a certificate with the given ID.
func (g *gatewayService) DeleteID(ctx context.Context, id string) error {
	err := g.keyStore.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, keystore.ErrRecordNotFound) {
			return fmt.Errorf("delete certificate: %v: %w", err, ErrCertificateNotFound)
		}

		return fmt.Errorf("delete certificate: %v: %w", err, ErrCertificateDelete)
	}

	return nil
}

// Ping checks whether the MFCR server is online. It returns nil if the response status is OK.
func (g *gatewayService) PingEET() error {
	if err := g.fscrClient.Ping(); err != nil {
		return fmt.Errorf("ping MFCR server: %v: %w", err, ErrFSCRConnection)
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
