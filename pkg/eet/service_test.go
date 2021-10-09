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
	"testing"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

type ks struct {
	key *rsa.PrivateKey
	crt *x509.Certificate
}

var okCertID = "valid"

func (ks *ks) Get(id string) (*keystore.KeyPair, error) {
	if id != okCertID {
		return nil, errors.New("certificate id not found")
	}

	return &keystore.KeyPair{
		Cert: ks.crt,
		Key:  ks.key,
	}, nil
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
		name    string
		url     string
		crtPool *x509.CertPool
		ok      bool
	}{
		{
			name:    "playground url",
			url:     fscr.PlaygroundURL,
			crtPool: mustParseCertPool(x509.SystemCertPool),
			ok:      true,
		},
		{
			name:    "production url",
			url:     fscr.ProductionURL,
			crtPool: mustParseCertPool(x509.SystemCertPool),
			ok:      true,
		},
		{
			name:    "invalid url",
			url:     "invalid_url",
			crtPool: mustParseCertPool(x509.SystemCertPool),
			ok:      false,
		},
		{
			name:    "invalid certificate",
			url:     fscr.PlaygroundURL,
			crtPool: x509.NewCertPool(),
			ok:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:            tc.crtPool,
						InsecureSkipVerify: false,
						MinVersion:         tls.VersionTLS13,
					},
				},
			}

			client := fscr.NewClient(c, tc.url)
			gSvc := eet.NewGatewayService(client, nil, nil)

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
	p12File, err := ioutil.ReadFile("testdata/EET_CA1_Playground-CZ00000019.p12")
	require.NoError(t, err, "file exists")

	roots, err := ca.PlaygroundRoots()
	require.NoError(t, err, "playground roots should be accessiable")

	crt, pk, err := wsse.ParseTaxpayerCertificate(roots, p12File, "eet")
	require.NoError(t, err, "valid taxpayer's PKCS12 file")

	invalidPK, err := rsa.GenerateKey(rand.Reader, 16)
	require.NoError(t, err, "generate random private key")

	systemCertPool, err := x509.SystemCertPool()
	require.NoError(t, err, "system root certificate pool should be accessible")

	icaCertPool, err := x509.SystemCertPool()
	require.NoError(t, err, "system root certificate pool should be accessible")
	ok := icaCertPool.AppendCertsFromPEM(ca.ICACertificate)
	require.True(t, ok, "ICA certificate is valid")

	tests := []struct {
		name   string
		certID string
		trzba  *eet.TrzbaType
		client fscr.Client
		ca     fscr.CAService
		ks     keystore.Service
		expErr error
	}{
		{
			name:   "ok",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
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
			ca: fscr.NewCAService(icaCertPool),
			ks: &ks{
				crt: crt,
				key: pk,
			},
			expErr: nil,
		},
		{
			name:   "invalid id",
			certID: "invalid_id",
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
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
			ca: fscr.NewCAService(icaCertPool),
			ks: &ks{
				crt: crt,
				key: pk,
			},
			expErr: eet.ErrCertificateRetrieval,
		},
		{
			name:   "invalid taxpayer's certificate",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
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
			ca: fscr.NewCAService(icaCertPool),
			ks: &ks{
				crt: crt,
				key: invalidPK,
			},
			expErr: eet.ErrRequestConstruction,
		},
		{
			name:   "invalid url",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
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
			ca: fscr.NewCAService(icaCertPool),
			ks: &ks{
				crt: crt,
				key: pk,
			},
			expErr: eet.ErrMFCRConnection,
		},
		{
			name:   "unknown CA for TLS",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
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
			ca: fscr.NewCAService(icaCertPool),
			ks: &ks{
				crt: crt,
				key: pk,
			},
			expErr: eet.ErrMFCRConnection,
		},
		{
			name:   "unknown EET CA certificate",
			certID: okCertID,
			trzba: &eet.TrzbaType{
				Hlavicka: eet.TrzbaHlavickaType{
					Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
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
			ca: fscr.NewCAService(x509.NewCertPool()),
			ks: &ks{
				crt: crt,
				key: pk,
			},
			expErr: eet.ErrMFCRResponseVerification,
		},
	}

	for _, tc := range tests {
		time.Sleep(1 * time.Second)

		t.Run(tc.name, func(t *testing.T) {
			gSvc := eet.NewGatewayService(tc.client, tc.ca, tc.ks)

			odp, err := gSvc.Send(context.Background(), tc.certID, tc.trzba)
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
