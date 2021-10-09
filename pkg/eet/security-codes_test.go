package eet_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/stretchr/testify/require"
)

var pkpTestSet = []struct {
	pfxFile   string
	plaintext string
	expPkpB64 []byte
}{
	{
		pfxFile:   "testdata/EET_CA1_Playground-CZ00000019.p12",
		plaintext: "CZ00000019|141|1patro-vpravo|141-18543-05|2019-08-11T15:36:14+02:00|236.00",
		expPkpB64: []byte("LnIZVjGlkdvO55gRP9Wa4k48X0QZrLU5aWsFDpYlwcCC/S8KHuUI0hxxS9pPP/vhuvKhe+a2YoZJ6wZDMSlPs0QDtt5i6D6XhQx/Oj84Azoo8fgSf5R6QOpnpsmw+X75jsUlwzGm4+YLGrhbScjdUdHIBLw2XCJus5cPXAb3aWcab59X2L/zaZ87oJRIQsmERMgPBtT8GIZNEfnX89OL/EMyyxibUC0C97aEokK1Lvvm55xidC9wWoMJJtKjNjScsGg5HpmOe0Zqekovtyvwt5mYVCx/fXa3OTsas2vVMskZKLyaxd7GYkJ5Y9nWCyuD8/pzKWR/8BxApIL601VHaQ=="),
	},
	{
		pfxFile:   "testdata/EET_CA1_Playground-CZ1212121218.p12",
		plaintext: "CZ1212121218|141|1patro-vpravo|141-18543-05|2019-08-11T15:36:14+02:00|236.00",
		expPkpB64: []byte("R6Q9JR65KiQA3C5a5NNxVT/vzUV1w3DJJ49QbUgsTsCmnSQHoXFL9bOr9C4c1rQO//fI5OdsZsuvHiwu9aY8rroyb63YMTK4aq77k+9KS8gLdkUk1V3h1DdaV03qeZIeNSmQZZ0NRqFTfVvqcbmAO3bLQOLAS6cEyfWc80egQntBmVE/eOMsnDk5zSjK1K/srS7jDX8zeZYW+ZJSCIy2t2VMxF5PNABXWcs09at7Wa0l+tpLTp8kjAJdAQQLwExrbymT0osaMWtqFhSW27bEf+fWXm0FerXTcLSPwaiIqJWjPSyQQdoc3HUkqjchjWcvuLQrnWhVLF97Kb87hWlOwQ=="),
	},
	{
		pfxFile:   "testdata/EET_CA1_Playground-CZ683555118.p12",
		plaintext: "CZ683555118|141|1patro-vpravo|141-18543-05|2019-08-11T15:36:14+02:00|236.00",
		expPkpB64: []byte("OpFQuM1bRD4kMVLsMIkg8eglTwSMX65w4UJ4RwkbqHhe7IW/MCW//0rlp2b0FRzssM3tmXpinzPRX3wUy+smjeek1wPZ2fDypPG2nf5WSDXpPOg4wjbMI97e906A9uZCvJY7XY9z67fjxHsUr5GnI5Lj2kc1Qiv7x7J6MxKkF0Z3mwOJTxL9qKtnEz/ZIMgovj/aMbb0c3Lg2VZQFSL5ZSnEGj6flT2v3//swEwSLF7xVsyimKKzVE1B/QuIAxZ9tUYjHoZiDmtOPcScYx4D9YsjsBf4tNmqbDDUSmY7dksGx2JOZkWfQ8YHU/nz0JF/yF7P2RT1IMpPUz6IPMc+Yg=="),
	},
}

func TestPkp(t *testing.T) {
	for _, tc := range pkpTestSet {
		t.Run(fmt.Sprintf("calculate pkp %s", tc.plaintext), func(t *testing.T) {
			_, pk := parseTaxpayerCertificate(t, tc.pfxFile)

			pkp, err := eet.Pkp(tc.plaintext, pk)
			require.NoError(t, err, "calculate pkp")
			pkpB64 := base64.StdEncoding.EncodeToString(pkp)

			require.Equal(t, string(tc.expPkpB64), pkpB64, "pkp of the same TrzbaType and certificate")
		})
	}
}

func TestBkp(t *testing.T) {
	tests := []struct {
		pkp    []byte
		expBkp []byte
	}{
		{
			pkp:    []byte("LnIZVjGlkdvO55gRP9Wa4k48X0QZrLU5aWsFDpYlwcCC/S8KHuUI0hxxS9pPP/vhuvKhe+a2YoZJ6wZDMSlPs0QDtt5i6D6XhQx/Oj84Azoo8fgSf5R6QOpnpsmw+X75jsUlwzGm4+YLGrhbScjdUdHIBLw2XCJus5cPXAb3aWcab59X2L/zaZ87oJRIQsmERMgPBtT8GIZNEfnX89OL/EMyyxibUC0C97aEokK1Lvvm55xidC9wWoMJJtKjNjScsGg5HpmOe0Zqekovtyvwt5mYVCx/fXa3OTsas2vVMskZKLyaxd7GYkJ5Y9nWCyuD8/pzKWR/8BxApIL601VHaQ=="),
			expBkp: []byte("ABA7EB19-7AD8D753-60ED57B3-9AC9957E-C192030B"),
		},
		{
			pkp:    []byte("R6Q9JR65KiQA3C5a5NNxVT/vzUV1w3DJJ49QbUgsTsCmnSQHoXFL9bOr9C4c1rQO//fI5OdsZsuvHiwu9aY8rroyb63YMTK4aq77k+9KS8gLdkUk1V3h1DdaV03qeZIeNSmQZZ0NRqFTfVvqcbmAO3bLQOLAS6cEyfWc80egQntBmVE/eOMsnDk5zSjK1K/srS7jDX8zeZYW+ZJSCIy2t2VMxF5PNABXWcs09at7Wa0l+tpLTp8kjAJdAQQLwExrbymT0osaMWtqFhSW27bEf+fWXm0FerXTcLSPwaiIqJWjPSyQQdoc3HUkqjchjWcvuLQrnWhVLF97Kb87hWlOwQ=="),
			expBkp: []byte("B088DC4E-FEDB1470-9E36E25F-65A8D680-6B774F9A"),
		},
		{
			pkp:    []byte("OpFQuM1bRD4kMVLsMIkg8eglTwSMX65w4UJ4RwkbqHhe7IW/MCW//0rlp2b0FRzssM3tmXpinzPRX3wUy+smjeek1wPZ2fDypPG2nf5WSDXpPOg4wjbMI97e906A9uZCvJY7XY9z67fjxHsUr5GnI5Lj2kc1Qiv7x7J6MxKkF0Z3mwOJTxL9qKtnEz/ZIMgovj/aMbb0c3Lg2VZQFSL5ZSnEGj6flT2v3//swEwSLF7xVsyimKKzVE1B/QuIAxZ9tUYjHoZiDmtOPcScYx4D9YsjsBf4tNmqbDDUSmY7dksGx2JOZkWfQ8YHU/nz0JF/yF7P2RT1IMpPUz6IPMc+Yg=="),
			expBkp: []byte("F6C463E7-030BB690-D0B39501-61B65E1A-672AA563"),
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("calculate bkp %s", tc.expBkp), func(t *testing.T) {
			// the bkp is calculated from the raw value of PKP (not encoded to base64)
			pkp, err := base64.StdEncoding.DecodeString(string(tc.pkp))
			require.NoError(t, err, "retrieve raw value of the pkp")

			bkp := eet.Bkp(pkp)
			require.Equal(t, string(tc.expBkp), string(bkp), "from the same pkp value")
		})
	}
}

func TestSetDelimiters(t *testing.T) {
	tests := []struct {
		bkpB64 []byte
		expBkp []byte
	}{
		{
			bkpB64: []byte("ABA7EB197AD8D75360ED57B39AC9957EC192030B"),
			expBkp: []byte("ABA7EB19-7AD8D753-60ED57B3-9AC9957E-C192030B"),
		},
		{
			bkpB64: []byte("B088DC4EFEDB14709E36E25F65A8D6806B774F9A"),
			expBkp: []byte("B088DC4E-FEDB1470-9E36E25F-65A8D680-6B774F9A"),
		},
		{
			bkpB64: []byte("F6C463E7030BB690D0B3950161B65E1A672AA563"),
			expBkp: []byte("F6C463E7-030BB690-D0B39501-61B65E1A-672AA563"),
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("bkp %s", tc.bkpB64), func(t *testing.T) {
			bkp := eet.SetDelimiters(tc.bkpB64)
			require.Equal(t, string(tc.expBkp), string(bkp), "set delimiters")
		})
	}
}
