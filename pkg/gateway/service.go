package gateway

import (
	"context"
	"errors"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"go.uber.org/multierr"
)

// ErrCertificateNotFound is returned if a certificate with the given ID can't be found.
var ErrCertificateNotFound = errors.New("taxpayer's certificate not found")

// ErrIDAlreadyExists is returned if a certificate with the given ID already exists.
var ErrIDAlreadyExists = errors.New("taxpayer's certificate with the id already exists")

// ErrCertificateParse is returned if a certificate can't be parsed.
var ErrCertificateParse = errors.New("taxpayer's certificate not parsable")

// ErrInvalidCertificatePassword is returned if the given password can't open sealed certificate and private key.
var ErrInvalidCertificatePassword = errors.New("invalid password for the decryption of the taxpayer's certificate")

// ErrRequestBuild is returned if a SOAP request envelope can't be built.
var ErrRequestBuild = errors.New("SOAP request to FSCR not completed")

// ErrFSCRConnection is returned if an error occurs during the communication with the FSCR servers.
var ErrFSCRConnection = errors.New("bad FSCR connection")

// ErrFSCRResponseParse is returned if an error occurs during the FSCR SOAP response parsing.
var ErrFSCRResponseParse = errors.New("invalid FSCR response structure")

// ErrFSCRResponseVerify is returned if the response doesn't pass security checks and verifications.
var ErrFSCRResponseVerify = errors.New("FSCR response not verified")

// ErrInvalidTaxpayersCertificate is returned if an invalid taxpayer's certificate is given.
var ErrInvalidTaxpayersCertificate = errors.New("invalid taxpayer's certificate")

// ErrMaxTXAttempts is returned if the maximum number of transaction attempts is reached.
var ErrMaxTXAttempts = errors.New("request discarded caused by maximum transaction attempts")

// ErrKeystoreUnavailable is returned if the keystore service can't be reached.
var ErrKeystoreUnavailable = errors.New("keystore service unavailable")

// ErrKeystoreUnexpected is returned if an unexpected error occurs.
var ErrKeystoreUnexpected = errors.New("unexpected keystore error")

// Service handles all functionalities provided by the EET Gateway.
type Service interface {
	Ping(ctx context.Context) error
	SendSale(ctx context.Context, certID string, pk []byte, trzba *eet.TrzbaType) (*eet.OdpovedType, error)
	StoreCert(ctx context.Context, certID string, password []byte, pkcsData []byte, pkcsPassword string) error
	ListCertIDs(ctx context.Context, start, end int64) ([]string, error)
	UpdateCertID(ctx context.Context, oldID, newID string) error
	UpdateCertPassword(ctx context.Context, id string, oldPassword, newPassword []byte) error
	DeleteID(ctx context.Context, id string) error
}

type service struct {
	fscrClient fscr.Client
	caSvc      fscr.CAService
	keyStore   keystore.Service
}

// Ping checks whether the FSCR servers are online. It returns nil if the response status is OK.
func (g *service) Ping(ctx context.Context) (err error) {
	if e := g.fscrClient.Ping(); e != nil {
		err = multierr.Append(err, ErrFSCRConnection)
	}

	if e := g.keyStore.Ping(ctx); e != nil {
		err = multierr.Append(err, ErrKeystoreUnavailable)
	}

	return err
}

// SendSale sends TrzbaType using fscr.Client, validates and verifies response and returns OdpovedType.
func (g *service) SendSale(ctx context.Context, certID string, certPassword []byte, trzba *eet.TrzbaType) (*eet.OdpovedType, error) {
	kp, err := g.keyStore.Get(ctx, certID, certPassword)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrRecordNotFound):
			return nil, multierr.Append(err, ErrCertificateNotFound)
		case errors.Is(err, keystore.ErrInvalidDecryptionKey):
			return nil, multierr.Append(err, ErrInvalidCertificatePassword)
		case errors.Is(err, keystore.ErrReachedMaxAttempts):
			return nil, multierr.Append(err, ErrMaxTXAttempts)
		case g.keyStore.Ping(ctx) != nil:
			return nil, multierr.Append(err, ErrKeystoreUnavailable)
		}

		return nil, multierr.Append(err, ErrKeystoreUnexpected)
	}

	reqEnv, err := eet.NewRequestEnvelope(trzba, kp.Cert, kp.PK)
	if err != nil {
		return nil, multierr.Append(err, ErrRequestBuild)
	}

	respEnv, err := g.fscrClient.Do(ctx, reqEnv)
	if err != nil {
		return nil, multierr.Append(err, ErrFSCRConnection)
	}

	odpoved, err := eet.ParseResponseEnvelope(respEnv)
	if err != nil {
		return nil, multierr.Append(err, ErrFSCRResponseParse)
	}

	err = eet.VerifyResponse(trzba, respEnv, odpoved, g.caSvc.VerifyDSig)
	if err != nil {
		return nil, multierr.Append(err, ErrFSCRResponseVerify)
	}

	return odpoved, nil
}

// StoreCert verifies and stores the taxpayer's certificate.
func (g *service) StoreCert(ctx context.Context, id string, password []byte, pkcsData []byte, pkcsPassword string) error {
	cert, pk, err := g.caSvc.ParseTaxpayerCertificate(pkcsData, pkcsPassword)
	if err != nil {
		if errors.Is(err, fscr.ErrInvalidCertificate) {
			return multierr.Append(err, ErrInvalidTaxpayersCertificate)
		}

		return multierr.Append(err, ErrCertificateParse)
	}

	err = g.keyStore.Store(ctx, id, password, &keystore.KeyPair{
		Cert: cert,
		PK:   pk,
	})
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrIDAlreadyExists):
			return multierr.Append(err, ErrIDAlreadyExists)
		case errors.Is(err, keystore.ErrReachedMaxAttempts):
			return multierr.Append(err, ErrMaxTXAttempts)
		case g.keyStore.Ping(ctx) != nil:
			return multierr.Append(err, ErrKeystoreUnavailable)
		}

		return multierr.Append(err, ErrKeystoreUnexpected)
	}

	return nil
}

// ListCertIDs returns the list of all certificate IDs in the keystore.
func (g *service) ListCertIDs(ctx context.Context, start, end int64) ([]string, error) {
	ids, err := g.keyStore.List(ctx, start, end)
	if err != nil {
		if g.keyStore.Ping(ctx) != nil {
			return nil, multierr.Append(err, ErrKeystoreUnavailable)
		}

		return nil, multierr.Append(err, ErrKeystoreUnexpected)
	}

	return ids, nil
}

// UpdateCertID updates the ID of the certificate.
func (g *service) UpdateCertID(ctx context.Context, oldID, newID string) error {
	err := g.keyStore.UpdateID(ctx, oldID, newID)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrRecordNotFound):
			return multierr.Append(err, ErrCertificateNotFound)
		case errors.Is(err, keystore.ErrIDAlreadyExists):
			return multierr.Append(err, ErrIDAlreadyExists)
		case errors.Is(err, keystore.ErrReachedMaxAttempts):
			return multierr.Append(err, ErrMaxTXAttempts)
		case g.keyStore.Ping(ctx) != nil:
			return multierr.Append(err, ErrKeystoreUnavailable)
		}

		return multierr.Append(err, ErrKeystoreUnexpected)
	}

	return nil
}

// UpdateCertPassword updates the password of the certificate.
func (g *service) UpdateCertPassword(ctx context.Context, id string, oldPassword, newPassword []byte) error {
	err := g.keyStore.UpdatePassword(ctx, id, oldPassword, newPassword)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrRecordNotFound):
			return multierr.Append(err, ErrCertificateNotFound)
		case errors.Is(err, keystore.ErrInvalidDecryptionKey):
			return multierr.Append(err, ErrInvalidCertificatePassword)
		case errors.Is(err, keystore.ErrReachedMaxAttempts):
			return multierr.Append(err, ErrMaxTXAttempts)
		case g.keyStore.Ping(ctx) != nil:
			return multierr.Append(err, ErrKeystoreUnavailable)
		}

		return multierr.Append(err, ErrKeystoreUnexpected)
	}

	return nil
}

// DeleteID removes a certificate with the given ID.
func (g *service) DeleteID(ctx context.Context, id string) error {
	err := g.keyStore.Delete(ctx, id)
	if err != nil {
		switch {
		case errors.Is(err, keystore.ErrRecordNotFound):
			return multierr.Append(err, ErrCertificateNotFound)
		case errors.Is(err, keystore.ErrReachedMaxAttempts):
			return multierr.Append(err, ErrMaxTXAttempts)
		case g.keyStore.Ping(ctx) != nil:
			return multierr.Append(err, ErrKeystoreUnavailable)
		}

		return multierr.Append(err, ErrKeystoreUnexpected)
	}

	return nil
}

// NewService returns Service implementation.
func NewService(fscrClient fscr.Client, eetCASvc fscr.CAService, keyStore keystore.Service) Service {
	return &service{
		fscrClient: fscrClient,
		caSvc:      eetCASvc,
		keyStore:   keyStore,
	}
}
