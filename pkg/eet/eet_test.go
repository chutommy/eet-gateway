package eet_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func readFile(t require.TestingT, path string) []byte {
	raw, err := ioutil.ReadFile(path)
	require.NoError(t, err, "read file")
	return raw
}

func mustDecodeB64(src []byte) []byte {
	raw, err := base64.StdEncoding.DecodeString(string(src))
	if err != nil {
		panic(err)
	}

	return raw
}

func mustParseTime(s string) time.Time {
	t, err := parseTime(s)
	if err != nil {
		panic(err)
	}

	return t
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(eet.DateTimeLayout, s)
	if err != nil {
		return t, fmt.Errorf("invalid time format: %w", err)
	}

	return t, nil
}

func parseTaxpayerCertificate(t require.TestingT, pfxFile string) (*x509.Certificate, *rsa.PrivateKey) {
	rawPK := readFile(t, pfxFile)
	roots, err := ca.PlaygroundRoots()
	require.NoError(t, err, "retrieve playground roots")
	cert, pk, err := wsse.ParseTaxpayerCertificate(roots, rawPK, "eet")
	require.NoError(t, err, "parse taxpayer's private key")

	return cert, pk
}

func TestDateTimeLayout(t *testing.T) {
	t1, err := parseTime("2019-08-11T15:37:52+02:00")
	require.NoError(t, err, "valid time format")
	require.NotZero(t, t1, "not zero time value")

	t2, err := parseTime("2019-08-11D15:37:52+02:00")
	require.Error(t, err, "invalid time format")
	require.Zero(t, t2, "invalid time format, zero time expected")
}

var trzbaSet = []struct {
	requestFile string
	pfxFile     string
	trzba       *eet.TrzbaType
}{
	{
		requestFile: "testdata/request_1.xml",
		pfxFile:     "testdata/EET_CA1_Playground-CZ00000019.p12",
		trzba: &eet.TrzbaType{
			Hlavicka: eet.TrzbaHlavickaType{
				Uuidzpravy:   "878b2e10-c4a5-4f05-8c90-abc181cd6837",
				Datodesl:     eet.DateTime(mustParseTime("2019-08-11T15:36:25+02:00")),
				Prvnizaslani: true,
				Overeni:      false,
			},
			Data: eet.TrzbaDataType{
				Dicpopl:   "CZ00000019",
				Idprovoz:  141,
				Idpokl:    "1patro-vpravo",
				Poradcis:  "141-18543-05",
				Dattrzby:  eet.DateTime(mustParseTime("2019-08-11T15:36:14+02:00")),
				Celktrzba: 236.00,
				Zakldan1:  100.00,
				Dan1:      21.00,
				Zakldan2:  100.00,
				Dan2:      15.00,
				Rezim:     0,
			},
			KontrolniKody: eet.TrzbaKontrolniKodyType{
				Pkp: eet.PkpElementType{
					PkpType:  mustDecodeB64(eet.PkpType("LnIZVjGlkdvO55gRP9Wa4k48X0QZrLU5aWsFDpYlwcCC/S8KHuUI0hxxS9pPP/vhuvKhe+a2YoZJ6wZDMSlPs0QDtt5i6D6XhQx/Oj84Azoo8fgSf5R6QOpnpsmw+X75jsUlwzGm4+YLGrhbScjdUdHIBLw2XCJus5cPXAb3aWcab59X2L/zaZ87oJRIQsmERMgPBtT8GIZNEfnX89OL/EMyyxibUC0C97aEokK1Lvvm55xidC9wWoMJJtKjNjScsGg5HpmOe0Zqekovtyvwt5mYVCx/fXa3OTsas2vVMskZKLyaxd7GYkJ5Y9nWCyuD8/pzKWR/8BxApIL601VHaQ==")),
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
		},
	},
	{
		requestFile: "testdata/request_2.xml",
		pfxFile:     "testdata/EET_CA1_Playground-CZ1212121218.p12",
		trzba: &eet.TrzbaType{
			Hlavicka: eet.TrzbaHlavickaType{
				Uuidzpravy:   "b9bd618a-7d3d-4a15-a405-bc9d0aba4e9b",
				Datodesl:     eet.DateTime(mustParseTime("2019-08-11T15:37:27+02:00")),
				Prvnizaslani: true,
				Overeni:      false,
			},
			Data: eet.TrzbaDataType{
				Dicpopl:   "CZ1212121218",
				Idprovoz:  141,
				Idpokl:    "1patro-vpravo",
				Poradcis:  "141-18543-05",
				Dattrzby:  eet.DateTime(mustParseTime("2019-08-11T15:36:14+02:00")),
				Celktrzba: 236.00,
				Zakldan1:  100.00,
				Dan1:      21.00,
				Zakldan2:  100.00,
				Dan2:      15.00,
				Rezim:     0,
			},
			KontrolniKody: eet.TrzbaKontrolniKodyType{
				Pkp: eet.PkpElementType{
					PkpType:  mustDecodeB64(eet.PkpType("R6Q9JR65KiQA3C5a5NNxVT/vzUV1w3DJJ49QbUgsTsCmnSQHoXFL9bOr9C4c1rQO//fI5OdsZsuvHiwu9aY8rroyb63YMTK4aq77k+9KS8gLdkUk1V3h1DdaV03qeZIeNSmQZZ0NRqFTfVvqcbmAO3bLQOLAS6cEyfWc80egQntBmVE/eOMsnDk5zSjK1K/srS7jDX8zeZYW+ZJSCIy2t2VMxF5PNABXWcs09at7Wa0l+tpLTp8kjAJdAQQLwExrbymT0osaMWtqFhSW27bEf+fWXm0FerXTcLSPwaiIqJWjPSyQQdoc3HUkqjchjWcvuLQrnWhVLF97Kb87hWlOwQ==")),
					Digest:   "SHA256",
					Cipher:   "RSA2048",
					Encoding: "base64",
				},
				Bkp: eet.BkpElementType{
					BkpType:  "B088DC4E-FEDB1470-9E36E25F-65A8D680-6B774F9A",
					Digest:   "SHA1",
					Encoding: "base16",
				},
			},
		},
	},
	{
		requestFile: "testdata/request_3.xml",
		pfxFile:     "testdata/EET_CA1_Playground-CZ683555118.p12",
		trzba: &eet.TrzbaType{
			Hlavicka: eet.TrzbaHlavickaType{
				Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
				Datodesl:     eet.DateTime(mustParseTime("2019-08-11T15:37:52+02:00")),
				Prvnizaslani: true,
				Overeni:      false,
			},
			Data: eet.TrzbaDataType{
				Dicpopl:   "CZ683555118",
				Idprovoz:  141,
				Idpokl:    "1patro-vpravo",
				Poradcis:  "141-18543-05",
				Dattrzby:  eet.DateTime(mustParseTime("2019-08-11T15:36:14+02:00")),
				Celktrzba: 236.00,
				Zakldan1:  100.00,
				Dan1:      21.00,
				Zakldan2:  100.00,
				Dan2:      15.00,
				Rezim:     0,
			},
			KontrolniKody: eet.TrzbaKontrolniKodyType{
				Pkp: eet.PkpElementType{
					PkpType:  mustDecodeB64(eet.PkpType("OpFQuM1bRD4kMVLsMIkg8eglTwSMX65w4UJ4RwkbqHhe7IW/MCW//0rlp2b0FRzssM3tmXpinzPRX3wUy+smjeek1wPZ2fDypPG2nf5WSDXpPOg4wjbMI97e906A9uZCvJY7XY9z67fjxHsUr5GnI5Lj2kc1Qiv7x7J6MxKkF0Z3mwOJTxL9qKtnEz/ZIMgovj/aMbb0c3Lg2VZQFSL5ZSnEGj6flT2v3//swEwSLF7xVsyimKKzVE1B/QuIAxZ9tUYjHoZiDmtOPcScYx4D9YsjsBf4tNmqbDDUSmY7dksGx2JOZkWfQ8YHU/nz0JF/yF7P2RT1IMpPUz6IPMc+Yg==")),
					Digest:   "SHA256",
					Cipher:   "RSA2048",
					Encoding: "base64",
				},
				Bkp: eet.BkpElementType{
					BkpType:  "F6C463E7-030BB690-D0B39501-61B65E1A-672AA563",
					Digest:   "SHA1",
					Encoding: "base16",
				},
			},
		},
	},
}

func TestTrzbaType_Etree(t *testing.T) {
	for _, tc := range trzbaSet {
		t.Run(tc.requestFile, func(t *testing.T) {
			// expected TrzbaType document
			src := readFile(t, tc.requestFile)
			doc := etree.NewDocument()
			err := doc.ReadFromBytes(src)
			require.NoError(t, err, "process etree document from the given request file: %w", err)
			trzbaElem := doc.FindElement("//Trzba")
			require.NotEmpty(t, trzbaElem, "find element Trzba")
			doc.SetRoot(trzbaElem)
			trzbaFromRequest, err := doc.WriteToBytes()
			require.NoError(t, err, "parse etree to string")

			var expTrzba *eet.TrzbaType
			err = xml.Unmarshal(trzbaFromRequest, &expTrzba)
			require.NoError(t, err, "unmarshal xml from sample request")

			expElem, err := expTrzba.Etree()
			require.NoError(t, err, "etree conversion")

			doc = etree.NewDocument()
			doc.SetRoot(expElem)
			expS, err := doc.WriteToString()
			require.NoError(t, err, "parse etree to string")

			// actual TrzbaType document
			elem, err := tc.trzba.Etree()
			require.NoError(t, err, "etree conversion")

			doc = etree.NewDocument()
			doc.SetRoot(elem)
			s, err := doc.WriteToString()
			require.NoError(t, err, "parse etree to string")

			require.EqualValues(t, expS, s, "same source")
		})
	}
}

func TestTrzbaType_SetSecurityCodes(t *testing.T) {
	for _, tc := range trzbaSet {
		t.Run(tc.pfxFile, func(t *testing.T) {
			_, pk := parseTaxpayerCertificate(t, tc.pfxFile)

			{
				// invalid private key
				invalidPk, err := rsa.GenerateKey(rand.Reader, 16)
				require.NoError(t, err, "generate rsa private key")
				err = tc.trzba.SetSecurityCodes(invalidPk)
				require.Error(t, err, "invalid private key")
			}

			// expected values
			expPkp := tc.trzba.KontrolniKody.Pkp
			expBkp := tc.trzba.KontrolniKody.Bkp

			// reset control codes
			tc.trzba.KontrolniKody.Pkp = eet.PkpElementType{}
			tc.trzba.KontrolniKody.Bkp = eet.BkpElementType{}

			// set security codes
			err := tc.trzba.SetSecurityCodes(pk)
			require.NoError(t, err, "set valid Trzba's security codes")

			// actual values
			pkp := tc.trzba.KontrolniKody.Pkp
			bkp := tc.trzba.KontrolniKody.Bkp

			require.Equal(t, expPkp, pkp, "no changes were made to the attributes, should be equal")
			require.Equal(t, expBkp, bkp, "same PKPs, digest values should be same")
		})
	}
}
