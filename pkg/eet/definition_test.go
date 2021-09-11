package eet_test

import (
	"encoding/xml"
	"fmt"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/stretchr/testify/require"
)

func parseTime(s string) time.Time {
	t, err := time.Parse("2006-01-02T15:04:05-07:00", s)
	if err != nil {
		panic(err)
	}

	return t
}

var trzbaSet = []struct {
	trzbaFile string
	trzba     *eet.TrzbaType
}{
	{
		trzbaFile: "testdata/request_1.xml",
		trzba: &eet.TrzbaType{
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
					PkpType:  eet.PkpType("LnIZVjGlkdvO55gRP9Wa4k48X0QZrLU5aWsFDpYlwcCC/S8KHuUI0hxxS9pPP/vhuvKhe+a2YoZJ6wZDMSlPs0QDtt5i6D6XhQx/Oj84Azoo8fgSf5R6QOpnpsmw+X75jsUlwzGm4+YLGrhbScjdUdHIBLw2XCJus5cPXAb3aWcab59X2L/zaZ87oJRIQsmERMgPBtT8GIZNEfnX89OL/EMyyxibUC0C97aEokK1Lvvm55xidC9wWoMJJtKjNjScsGg5HpmOe0Zqekovtyvwt5mYVCx/fXa3OTsas2vVMskZKLyaxd7GYkJ5Y9nWCyuD8/pzKWR/8BxApIL601VHaQ=="),
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
		trzbaFile: "testdata/request_2.xml",
		trzba: &eet.TrzbaType{
			Hlavicka: eet.TrzbaHlavickaType{
				Uuidzpravy:   "b9bd618a-7d3d-4a15-a405-bc9d0aba4e9b",
				Datodesl:     eet.DateTime(parseTime("2019-08-11T15:37:27+02:00")),
				Prvnizaslani: true,
				Overeni:      false,
			},
			Data: eet.TrzbaDataType{
				Dicpopl:   "CZ1212121218",
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
					PkpType:  eet.PkpType("R6Q9JR65KiQA3C5a5NNxVT/vzUV1w3DJJ49QbUgsTsCmnSQHoXFL9bOr9C4c1rQO//fI5OdsZsuvHiwu9aY8rroyb63YMTK4aq77k+9KS8gLdkUk1V3h1DdaV03qeZIeNSmQZZ0NRqFTfVvqcbmAO3bLQOLAS6cEyfWc80egQntBmVE/eOMsnDk5zSjK1K/srS7jDX8zeZYW+ZJSCIy2t2VMxF5PNABXWcs09at7Wa0l+tpLTp8kjAJdAQQLwExrbymT0osaMWtqFhSW27bEf+fWXm0FerXTcLSPwaiIqJWjPSyQQdoc3HUkqjchjWcvuLQrnWhVLF97Kb87hWlOwQ=="),
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
		trzbaFile: "testdata/request_3.xml",
		trzba: &eet.TrzbaType{
			Hlavicka: eet.TrzbaHlavickaType{
				Uuidzpravy:   "e0e80d09-1a19-45da-91d0-56121088ed49",
				Datodesl:     eet.DateTime(parseTime("2019-08-11T15:37:52+02:00")),
				Prvnizaslani: true,
				Overeni:      false,
			},
			Data: eet.TrzbaDataType{
				Dicpopl:   "CZ683555118",
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
					PkpType:  eet.PkpType("OpFQuM1bRD4kMVLsMIkg8eglTwSMX65w4UJ4RwkbqHhe7IW/MCW//0rlp2b0FRzssM3tmXpinzPRX3wUy+smjeek1wPZ2fDypPG2nf5WSDXpPOg4wjbMI97e906A9uZCvJY7XY9z67fjxHsUr5GnI5Lj2kc1Qiv7x7J6MxKkF0Z3mwOJTxL9qKtnEz/ZIMgovj/aMbb0c3Lg2VZQFSL5ZSnEGj6flT2v3//swEwSLF7xVsyimKKzVE1B/QuIAxZ9tUYjHoZiDmtOPcScYx4D9YsjsBf4tNmqbDDUSmY7dksGx2JOZkWfQ8YHU/nz0JF/yF7P2RT1IMpPUz6IPMc+Yg=="),
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
	for ti, tc := range trzbaSet {
		t.Run(fmt.Sprintf("Trzba message #%d", ti+1), func(t *testing.T) {
			elem, err := tc.trzba.Etree()
			require.NoError(t, err, "etree converting error")

			doc := etree.NewDocument()
			doc.SetRoot(elem)
			s, err := doc.WriteToString()
			require.NoError(t, err, "parse etree to string")

			expSrc := readFile(t, tc.trzbaFile)
			expT := new(eet.TrzbaType)
			err = xml.Unmarshal(expSrc, &expT)
			require.NoError(t, err, "unmarshal xml from sample request")

			expElem, err := expT.Etree()
			require.NoError(t, err, "etree converting error")

			expDoc := etree.NewDocument()
			expDoc.SetRoot(expElem.FindElement("//Trzba"))
			expS, err := doc.WriteToString()
			require.NoError(t, err, "parse etree to string")

			require.EqualValues(t, expS, s)
		})
	}
}
