package eet_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/mfcr"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func TestNewSoapEnvelope(t *testing.T) {
	for _, tc := range trzbaSet {
		t.Run(fmt.Sprintf("build soap envelope %s", tc.requestFile), func(t *testing.T) {
			// load certificate
			rawCrt := readFile(t, tc.crtFile)
			pemCrt, _ := pem.Decode(rawCrt)
			crt, err := wsse.ParseCertificate(pemCrt)
			require.NoError(t, err, "parse SSL certificate")

			// load private key
			rawPk := readFile(t, tc.pkFile)
			pemPk, _ := pem.Decode(rawPk)
			pk, err := wsse.ParsePrivateKey(pemPk)
			require.NoError(t, err, "parse private key")

			envelope, err := eet.NewRequestEnvelope(tc.trzba, crt, pk)
			require.NoError(t, err, "build a new valid SOAP envelope")
			require.NotEmpty(t, envelope, "valid TrzbaType and cert/pk key pair")

			// get actual trzba value of the envelope
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

func BenchmarkNewSoapEnvelope(b *testing.B) {
	tc := trzbaSet[0]

	rawCrt := readFile(b, tc.crtFile)
	pemCrt, _ := pem.Decode(rawCrt)
	crt, err := wsse.ParseCertificate(pemCrt)
	require.NoError(b, err, "parse SSL certificate")

	rawPk := readFile(b, tc.pkFile)
	pemPk, _ := pem.Decode(rawPk)
	pk, err := wsse.ParsePrivateKey(pemPk)
	require.NoError(b, err, "parse private key")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eet.NewRequestEnvelope(tc.trzba, crt, pk)
	}
}

var parseAndVerifyResponseTests = []struct {
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

func TestParseAndVerifyResponse(t *testing.T) {
	pool, err := x509.SystemCertPool()
	require.NoError(t, err, "system certificate pool")
	require.True(t, pool.AppendCertsFromPEM([]byte(mfcr.ICACertificate)), "valid PEM SSL certificate")
	caSvc := mfcr.NewCAService(pool)

	for _, tc := range parseAndVerifyResponseTests {
		t.Run(tc.name, func(t *testing.T) {
			resp := readFile(t, tc.respFile)

			odp, err := eet.ParseResponseEnvelope(resp)
			if err == nil {
				var trzba *eet.TrzbaType
				{
					// build TrzbaType to pass tests
					trzba = &eet.TrzbaType{
						Hlavicka: eet.TrzbaHlavickaType{
							Overeni: false,
						},
						KontrolniKody: eet.TrzbaKontrolniKodyType{
							Bkp: eet.BkpElementType{
								BkpType: eet.BkpType(tc.bkp),
							},
						},
					}
				}
				err = eet.VerifyResponse(trzba, resp, odp, caSvc.Verify)
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

func BenchmarkParseResponseEnvelope(b *testing.B) {
	respFile := "testdata/response_1.xml"
	resp := readFile(b, respFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eet.ParseResponseEnvelope(resp)
	}
}

func BenchmarkVerifyResponse(b *testing.B) {
	respFile := "testdata/response_1.xml"
	trzba := &eet.TrzbaType{
		KontrolniKody: eet.TrzbaKontrolniKodyType{
			Bkp: eet.BkpElementType{
				BkpType: "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
			},
		},
	}
	resp := readFile(b, respFile)
	odpoved, err := eet.ParseResponseEnvelope(resp)
	require.NoError(b, err, "parse valid response envelope")

	pool, err := x509.SystemCertPool()
	require.NoError(b, err, "retrieve system certificate pool")
	require.True(b, pool.AppendCertsFromPEM([]byte(mfcr.ICACertificate)), "valid SSL certificate")
	caSvc := mfcr.NewCAService(pool)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eet.VerifyResponse(trzba, resp, odpoved, caSvc.Verify)
	}
}
