package eet_test

import (
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/eet"
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
			require.NoError(t, err, "parse ssl certificate")

			// load private key
			rawPk := readFile(t, tc.pkFile)
			pemPk, _ := pem.Decode(rawPk)
			pk, err := wsse.ParsePrivateKey(pemPk)
			require.NoError(t, err, "parse private key")

			envelope, err := eet.NewRequestEnvelope(tc.trzba, crt, pk)
			require.NoError(t, err, "build a new SOAP envelope")
			require.NotEmpty(t, envelope, "no error returned")

			// get actual trzba value of the envelope
			doc := etree.NewDocument()
			err = doc.ReadFromBytes(envelope)
			require.NoError(t, err, "build a new document from the generated envelope")
			doc.SetRoot(doc.FindElement("./Envelope/Body/Trzba"))
			trzbaBytes, err := doc.WriteToBytes()
			require.NoError(t, err, "write trzba element from the generated envelope back to bytes")
			var actTrzba *eet.TrzbaType
			err = xml.Unmarshal(trzbaBytes, &actTrzba)
			require.NoError(t, err, "unmarshal generated envelope back to the TrzbaType")

			require.EqualValues(t, tc.trzba, actTrzba)
		})
	}
}

func BenchmarkNewSoapEnvelope(b *testing.B) {
	tc := trzbaSet[0]

	rawCrt := readFile(b, tc.crtFile)
	pemCrt, _ := pem.Decode(rawCrt)
	crt, err := wsse.ParseCertificate(pemCrt)
	require.NoError(b, err, "parse ssl certificate")

	rawPk := readFile(b, tc.pkFile)
	pemPk, _ := pem.Decode(rawPk)
	pk, err := wsse.ParsePrivateKey(pemPk)
	require.NoError(b, err, "parse private key")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eet.NewRequestEnvelope(tc.trzba, crt, pk)
	}
}
