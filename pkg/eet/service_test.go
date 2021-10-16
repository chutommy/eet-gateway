package eet_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func newUUID() eet.UUIDType {
	uuid, err := uuid.New().MarshalText()
	if err != nil {
		panic(err)
	}

	return eet.UUIDType(uuid)
}

type ks struct {
	id       string
	password []byte
	cert     *x509.Certificate
	pk       *rsa.PrivateKey
}

var okCertID = "valid"

func (k *ks) Store(ctx context.Context, id string, password []byte, kp *keystore.KeyPair) error {
	k.id = id
	k.password = password
	k.cert = kp.Cert
	k.pk = kp.PK
	return nil
}

func (k *ks) Delete(ctx context.Context, id string) error {
	k = &ks{}
	return nil
}

func (k *ks) Get(ctx context.Context, id string, password []byte) (*keystore.KeyPair, error) {
	if id != k.id || reflect.DeepEqual(password, &k) {
		return nil, errors.New("invalid verification (id/password)")
	}

	return &keystore.KeyPair{
		Cert: k.cert,
		PK:   k.pk,
	}, nil
}

func (k *ks) ChangePassword(ctx context.Context, id string, oldPassword, newPassword []byte) error {
	k.password = newPassword
	return nil
}

func (k *ks) ChangeID(ctx context.Context, oldID, newID string) error {
	k.id = newID
	return nil
}

func newKS(id string, password []byte, cert *x509.Certificate, pk *rsa.PrivateKey) *ks {
	return &ks{
		id:       id,
		password: password,
		cert:     cert,
		pk:       pk,
	}
}

func mustParseCertPool(f func() (*x509.CertPool, error)) *x509.CertPool {
	pool, err := f()
	if err != nil {
		panic(err)
	}

	return pool
}

func TestGatewayService_Ping(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		certPool *x509.CertPool
		ok       bool
	}{
		{
			name:     "playground url",
			url:      fscr.PlaygroundURL,
			certPool: mustParseCertPool(x509.SystemCertPool),
			ok:       true,
		},
		{
			name:     "production url",
			url:      fscr.ProductionURL,
			certPool: mustParseCertPool(x509.SystemCertPool),
			ok:       true,
		},
		{
			name:     "invalid url",
			url:      "invalid_url",
			certPool: mustParseCertPool(x509.SystemCertPool),
			ok:       false,
		},
		{
			name:     "invalid certificate",
			url:      fscr.PlaygroundURL,
			certPool: x509.NewCertPool(),
			ok:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// define dependencies of the GatewayService
			c := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:            tc.certPool,
						InsecureSkipVerify: false,
						MinVersion:         tls.VersionTLS13,
					},
				},
			}

			client := fscr.NewClient(c, tc.url)

			// construct the service
			gSvc := eet.NewGatewayService(client, nil, nil)

			// run
			err := gSvc.Ping()
			if tc.ok {
				require.NoError(t, err, "FSCR's servers should be available non-stop")
			} else {
				require.Error(t, err, "error expected")
			}
		})
	}
}

func TestGatewayService_Send(t *testing.T) {
	// CA root certificate
	roots, err := ca.PlaygroundRoots()
	require.NoError(t, err, "playground roots should be accessiable")

	// taxpayer's certificate/private key
	p12File, err := ioutil.ReadFile("testdata/EET_CA1_Playground-CZ00000019.p12")
	require.NoError(t, err, "file exists")

	cert, pk, err := wsse.ParseTaxpayerCertificate(roots, p12File, "eet")
	require.NoError(t, err, "valid taxpayer's PKCS12 file")

	invalidPK, err := rsa.GenerateKey(rand.Reader, 16)
	require.NoError(t, err, "generate random private key")

	// certificate pool for the HTTPS
	systemCertPool, err := x509.SystemCertPool()
	require.NoError(t, err, "system root certificate pool should be accessible")

	icaCertPool := x509.NewCertPool()
	ok := icaCertPool.AppendCertsFromPEM(ca.ICACertificate)
	require.True(t, ok, "ICA certificate is valid")

	tests := []struct {
		name   string
		certID string
		trzba  *eet.TrzbaType
		client fscr.Client
		eetCA  fscr.EETCAService
		ks     keystore.Service
		expErr error
	}{
		{
			name:   "ok",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   newUUID(),
					Datodesl:     eet.DateTime(time.Now().Truncate(time.Second)),
					Prvnizaslani: true,
					Overeni:      false,
				},
				Data: eet.TrzbaDataType{
					Dicpopl:         "CZ00000019",
					Dicpoverujiciho: "CZ683555118",
					Idprovoz:        42,
					Idpokl:          "1patro-vpravo",
					Poradcis:        "141-18543-05",
					Dattrzby:        eet.DateTime(time.Now().Truncate(time.Second)),
					Celktrzba:       100,
					Zakldan1:        100,
					Dan1:            21,
					Zakldan2:        100,
					Dan2:            15,
					Rezim:           0,
				},
			},
			client: fscr.NewClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    systemCertPool,
						MinVersion: tls.VersionTLS13,
					},
				},
			}, fscr.PlaygroundURL),
			eetCA:  fscr.NewEETCAService(icaCertPool),
			ks:     newKS(okCertID, []byte{}, cert, pk),
			expErr: nil,
		},
		{
			name:   "invalid id",
			certID: "invalid_id",
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   newUUID(),
					Datodesl:     eet.DateTime(time.Now().Truncate(time.Second)),
					Prvnizaslani: true,
					Overeni:      false,
				},
				Data: eet.TrzbaDataType{
					Dicpopl:         "CZ00000019",
					Dicpoverujiciho: "CZ683555118",
					Idprovoz:        42,
					Idpokl:          "1patro-vpravo",
					Poradcis:        "141-18543-05",
					Dattrzby:        eet.DateTime(time.Now().Truncate(time.Second)),
					Celktrzba:       100,
					Zakldan1:        100,
					Dan1:            21,
					Zakldan2:        100,
					Dan2:            15,
					Rezim:           0,
				},
			},
			client: fscr.NewClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    systemCertPool,
						MinVersion: tls.VersionTLS13,
					},
				},
			}, fscr.PlaygroundURL),
			eetCA:  fscr.NewEETCAService(icaCertPool),
			ks:     newKS(okCertID, []byte{}, cert, pk),
			expErr: eet.ErrCertificateRetrieval,
		},
		{
			name:   "invalid taxpayer's certificate",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   newUUID(),
					Datodesl:     eet.DateTime(time.Now().Truncate(time.Second)),
					Prvnizaslani: true,
					Overeni:      false,
				},
				Data: eet.TrzbaDataType{
					Dicpopl:         "CZ00000019",
					Dicpoverujiciho: "CZ683555118",
					Idprovoz:        42,
					Idpokl:          "1patro-vpravo",
					Poradcis:        "141-18543-05",
					Dattrzby:        eet.DateTime(time.Now().Truncate(time.Second)),
					Celktrzba:       100,
					Zakldan1:        100,
					Dan1:            21,
					Zakldan2:        100,
					Dan2:            15,
					Rezim:           0,
				},
			},
			client: fscr.NewClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    systemCertPool,
						MinVersion: tls.VersionTLS13,
					},
				},
			}, fscr.PlaygroundURL),
			eetCA:  fscr.NewEETCAService(icaCertPool),
			ks:     newKS(okCertID, []byte{}, cert, invalidPK),
			expErr: eet.ErrRequestConstruction,
		},
		{
			name:   "invalid url",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   newUUID(),
					Datodesl:     eet.DateTime(time.Now().Truncate(time.Second)),
					Prvnizaslani: true,
					Overeni:      false,
				},
				Data: eet.TrzbaDataType{
					Dicpopl:         "CZ00000019",
					Dicpoverujiciho: "CZ683555118",
					Idprovoz:        42,
					Idpokl:          "1patro-vpravo",
					Poradcis:        "141-18543-05",
					Dattrzby:        eet.DateTime(time.Now().Truncate(time.Second)),
					Celktrzba:       100,
					Zakldan1:        100,
					Dan1:            21,
					Zakldan2:        100,
					Dan2:            15,
					Rezim:           0,
				},
			},
			client: fscr.NewClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    systemCertPool,
						MinVersion: tls.VersionTLS13,
					},
				},
			}, "invalid_url"),
			eetCA:  fscr.NewEETCAService(icaCertPool),
			ks:     newKS(okCertID, []byte{}, cert, pk),
			expErr: eet.ErrMFCRConnection,
		},
		{
			name:   "unknown CA for TLS",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   newUUID(),
					Datodesl:     eet.DateTime(time.Now().Truncate(time.Second)),
					Prvnizaslani: true,
					Overeni:      false,
				},
				Data: eet.TrzbaDataType{
					Dicpopl:         "CZ00000019",
					Dicpoverujiciho: "CZ683555118",
					Idprovoz:        42,
					Idpokl:          "1patro-vpravo",
					Poradcis:        "141-18543-05",
					Dattrzby:        eet.DateTime(time.Now().Truncate(time.Second)),
					Celktrzba:       100,
					Zakldan1:        100,
					Dan1:            21,
					Zakldan2:        100,
					Dan2:            15,
					Rezim:           0,
				},
			},
			client: fscr.NewClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    x509.NewCertPool(),
						MinVersion: tls.VersionTLS13,
					},
				},
			}, fscr.PlaygroundURL),
			eetCA:  fscr.NewEETCAService(icaCertPool),
			ks:     newKS(okCertID, []byte{}, cert, pk),
			expErr: eet.ErrMFCRConnection,
		},
		{
			name:   "unknown EET CA certificate",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   newUUID(),
					Datodesl:     eet.DateTime(time.Now().Truncate(time.Second)),
					Prvnizaslani: true,
					Overeni:      false,
				},
				Data: eet.TrzbaDataType{
					Dicpopl:         "CZ00000019",
					Dicpoverujiciho: "CZ683555118",
					Idprovoz:        42,
					Idpokl:          "1patro-vpravo",
					Poradcis:        "141-18543-05",
					Dattrzby:        eet.DateTime(time.Now().Truncate(time.Second)),
					Celktrzba:       100,
					Zakldan1:        100,
					Dan1:            21,
					Zakldan2:        100,
					Dan2:            15,
					Rezim:           0,
				},
			},
			client: fscr.NewClient(&http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    systemCertPool,
						MinVersion: tls.VersionTLS13,
					},
				},
			}, fscr.PlaygroundURL),
			eetCA:  fscr.NewEETCAService(x509.NewCertPool()),
			ks:     newKS(okCertID, []byte{}, cert, pk),
			expErr: eet.ErrMFCRResponseVerification,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// construct a service
			gSvc := eet.NewGatewayService(tc.client, tc.eetCA, tc.ks)

			// run
			odp, err := gSvc.Send(context.Background(), tc.certID, []byte{}, tc.trzba)
			if tc.expErr == nil {
				require.NoError(t, err, "sale should be successfully stored")
				require.NotNil(t, odp, "no error expected")

				require.NotEmpty(t, odp.Potvrzeni.Fik, "FIK should not be empty in successful response")
			} else {
				require.Error(t, err, "invalid case")
				require.ErrorIs(t, err, tc.expErr, "invalid case got away")
				require.Nil(t, odp, "no error expected")
			}
		})
	}
}
