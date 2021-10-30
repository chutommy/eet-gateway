package eet_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/stretchr/testify/require"
)

func decodeB64(src []byte) []byte {
	raw, err := base64.StdEncoding.DecodeString(string(src))
	if err != nil {
		panic(err)
	}

	return raw
}

func parseTime(s string) time.Time {
	t, err := time.Parse(eet.DateTimeLayout, s)
	if err != nil {
		panic(err)
	}

	return t
}

func parseTaxpayerCertificate(t require.TestingT, pfxFile string) (*x509.Certificate, *rsa.PrivateKey) {
	rawPK, err := ioutil.ReadFile(pfxFile)
	require.NoError(t, err)

	roots, err := ca.PlaygroundRoots()
	require.NoError(t, err)

	caSvc := fscr.NewCAService(roots, nil)
	cert, pk, err := caSvc.ParseTaxpayerCertificate(rawPK, "eet")
	require.NoError(t, err)

	return cert, pk
}

func TestNewSoapEnvelope(t *testing.T) {
	trzba := eet.TrzbaType{
		Hlavicka: eet.TrzbaHlavickaType{
			Uuidzpravy:   "878b2e10-c4a5-4f05-8c90-abc181cd6837",
			Datodesl:     eet.DateTime(parseTime("2019-08-11T15:36:25+02:00")),
			Prvnizaslani: true,
			Overeni:      false,
		},
		Data: eet.TrzbaDataType{
			Dicpopl:   "CZ00000019",
			Idprovoz:  141,
			Idpokl:    "1patro-vpravo",
			Poradcis:  "141-18543-05",
			Dattrzby:  eet.DateTime(parseTime("2019-08-11T15:36:14+02:00")),
			Celktrzba: 236.00,
			Zakldan1:  100.00,
			Dan1:      21.00,
			Zakldan2:  100.00,
			Dan2:      15.00,
			Rezim:     0,
		},
		KontrolniKody: eet.TrzbaKontrolniKodyType{
			Pkp: eet.PkpElementType{
				PkpType:  decodeB64(eet.PkpType("LnIZVjGlkdvO55gRP9Wa4k48X0QZrLU5aWsFDpYlwcCC/S8KHuUI0hxxS9pPP/vhuvKhe+a2YoZJ6wZDMSlPs0QDtt5i6D6XhQx/Oj84Azoo8fgSf5R6QOpnpsmw+X75jsUlwzGm4+YLGrhbScjdUdHIBLw2XCJus5cPXAb3aWcab59X2L/zaZ87oJRIQsmERMgPBtT8GIZNEfnX89OL/EMyyxibUC0C97aEokK1Lvvm55xidC9wWoMJJtKjNjScsGg5HpmOe0Zqekovtyvwt5mYVCx/fXa3OTsas2vVMskZKLyaxd7GYkJ5Y9nWCyuD8/pzKWR/8BxApIL601VHaQ==")),
				Digest:   "SHA256",
				Cipher:   "RSA2048",
				Encoding: "base64",
			},
			Bkp: eet.BkpElementType{
				BkpType:  "ABA7EB19-7AD8D753-60ED57B3-9AC9957E-C192030B",
				Digest:   "SHA1",
				Encoding: "base16",
			},
		},
	}

	cert, pk := parseTaxpayerCertificate(t, "testdata/EET_CA1_Playground-CZ00000019.p12")

	// pass a copy (control codes are internally set to the TrzbaType)
	trzbaCopy := trzba
	envelope, err := eet.NewRequestEnvelope(&trzbaCopy, cert, pk)
	require.NoError(t, err)

	// get the trzba value from the envelope
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(envelope)
	require.NoError(t, err)

	trzbaElem := doc.FindElement("//Trzba")
	doc.SetRoot(trzbaElem)

	trzbaBytes, err := doc.WriteToBytes()
	require.NoError(t, err)

	var processedTrzba eet.TrzbaType
	err = xml.Unmarshal(trzbaBytes, &processedTrzba)
	require.NoError(t, err)

	require.EqualValues(t, trzba, processedTrzba)
}

func TestParseAndVerifyResponse(t *testing.T) {
	tests := []struct {
		name     string
		respFile string
		bkp      string
		expErr   error
	}{
		{
			name:     "accepted sale",
			respFile: "testdata/response_1.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
		},
		{
			name:     "denied sale",
			respFile: "testdata/response_2.xml",
		},
		{
			name:     "invalid reference element",
			respFile: "testdata/response_3.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
			expErr:   rsa.ErrVerification,
		},
		{
			name:     "invalid digest",
			respFile: "testdata/response_4.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
			expErr:   eet.ErrInvalidXMLDigest,
		},
		{
			name:     "invalid signature",
			respFile: "testdata/response_5.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7372",
			expErr:   rsa.ErrVerification,
		},
		{
			name:     "invalid xml",
			respFile: "testdata/response_6.xml",
			expErr:   etree.ErrXML,
		},
		{
			name:     "invalid bkp",
			respFile: "testdata/response_7.xml",
			bkp:      "36FA2953-0E365CE7-5829441B-8CAFFB11-A89C7370",
			expErr:   eet.ErrInvalidBKP,
		},
	}

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.ICACertificate))
	eetCASvc := fscr.NewCAService(nil, pool)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := ioutil.ReadFile(tc.respFile)
			require.NoError(t, err)

			odp, err := eet.ParseResponseEnvelope(resp)
			if err == nil {
				// set TrzbaType with required control codes
				trzba := &eet.TrzbaType{
					Hlavicka: eet.TrzbaHlavickaType{
						Uuidzpravy: odp.Hlavicka.Uuidzpravy,
						Overeni:    false,
					},
					KontrolniKody: eet.TrzbaKontrolniKodyType{
						Bkp: eet.BkpElementType{
							BkpType: eet.BkpType(tc.bkp),
						},
					},
				}

				err = eet.VerifyResponse(trzba, resp, odp, eetCASvc.VerifyDSig)
			}

			if tc.expErr == nil {
				require.NoError(t, err)
				require.NotEmpty(t, odp)
			} else {
				require.ErrorIs(t, err, tc.expErr)
			}
		})
	}
}
