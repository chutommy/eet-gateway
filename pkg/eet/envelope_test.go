package eet_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/stretchr/testify/require"
)

func TestNewSoapEnvelope(t *testing.T) {
	for _, tc := range trzbaSet {
		t.Run(fmt.Sprintf("build soap envelope %s", tc.requestFile), func(t *testing.T) {
			crt, pk := parseTaxpayerCertificate(t, tc.pfxFile)

			envelope, err := eet.NewRequestEnvelope(tc.trzba, crt, pk)
			require.NoError(t, err, "build a new valid SOAP envelope")
			require.NotEmpty(t, envelope, "valid TrzbaType and cert/pk key pair")

			// get the actual trzba value of the envelope
			doc := etree.NewDocument()
			err = doc.ReadFromBytes(envelope)
			require.NoError(t, err, "build a new document from the generated envelope")

			trzbaElem := doc.FindElement("//Trzba")
			require.NotNil(t, trzbaElem, "find element Trzba")
			doc.SetRoot(trzbaElem)

			trzbaBytes, err := doc.WriteToBytes()
			require.NoError(t, err, "write trzba element from the generated envelope back to bytes")

			var actTrzba *eet.TrzbaType
			err = xml.Unmarshal(trzbaBytes, &actTrzba)
			require.NoError(t, err, "unmarshal generated envelope back to the TrzbaType")

			require.EqualValues(t, tc.trzba, actTrzba, "nothing modified")
		})
	}
}

func TestParseAndVerifyResponse(t *testing.T) {
	tests := []struct {
		name     string
		respFile string
		bkp      string
		expErr   error
		valid    bool
	}{
		{
			name:     "accepted sale",
			respFile: "testdata/response_1.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
			valid:    true,
		},
		{
			name:     "denied sale",
			respFile: "testdata/response_2.xml",
			valid:    true,
		},
		{
			name:     "invalid reference element",
			respFile: "testdata/response_3.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
			expErr:   rsa.ErrVerification,
			valid:    false,
		},
		{
			name:     "invalid digest",
			respFile: "testdata/response_4.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
			expErr:   eet.ErrInvalidDigest,
			valid:    false,
		},
		{
			name:     "invalid signature",
			respFile: "testdata/response_5.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
			expErr:   rsa.ErrVerification,
			valid:    false,
		},
		{
			name:     "invalid xml",
			respFile: "testdata/response_6.xml",
			expErr:   etree.ErrXML,
			valid:    false,
		},
		{
			name:     "invalid bkp",
			respFile: "testdata/response_7.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7370",
			expErr:   eet.ErrInvalidBKP,
			valid:    false,
		},
	}

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.ICACertificate), "valid PEM SSL certificate")
	eetCASvc := fscr.NewEETCAService(pool)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := readFile(t, tc.respFile)

			odp, err := eet.ParseResponseEnvelope(resp)
			if err == nil {
				// TrzbaType with required control codes
				trzba := &eet.TrzbaType{
					Hlavicka: eet.TrzbaHlavickaType{
						Overeni: false,
					},
					KontrolniKody: eet.TrzbaKontrolniKodyType{
						Bkp: eet.BkpElementType{
							BkpType: eet.BkpType(tc.bkp),
						},
					},
				}

				err = eet.VerifyResponse(trzba, resp, odp, eetCASvc.Verify)
			}

			if tc.valid {
				require.NoError(t, err, "valid test case")
				require.NotEmpty(t, odp, "valid response OdpovedType")
			} else {
				require.ErrorIs(t, err, tc.expErr, "invalid test case")
			}
		})
	}
}
