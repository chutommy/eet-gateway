package eet_test

import (
	"encoding/pem"
	"encoding/xml"
	"testing"

	"github.com/beevik/etree"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

func TestNewSoapEnvelope(t *testing.T) {
	var trzba = &eet.TrzbaType{
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
	}

	rawCrt := readFile(t, "testdata/EET_CA1_Playground-CZ00000019.crt")
	pemCrt, _ := pem.Decode(rawCrt)
	crt, err := wsse.ParseCertificate(pemCrt)
	require.NoError(t, err, "parse ssl certificate")

	rawPk := readFile(t, "testdata/EET_CA1_Playground-CZ00000019.key")
	pemPk, _ := pem.Decode(rawPk)
	pk, err := wsse.ParsePrivateKey(pemPk)
	require.NoError(t, err, "parse private key")

	envelope, err := eet.NewTrzbaEnvelope(trzba, crt, pk)
	require.NoError(t, err, "build a new SOAP envelope")
	require.NotEmpty(t, envelope, "no error returned")

	envelopeDoc := etree.NewDocument()
	err = envelopeDoc.ReadFromBytes(envelope)
	require.NoError(t, err, "build a new document from the generated envelope")
	trzbaElem := envelopeDoc.FindElement("./Envelope/Body/Trzba")
	trzbaDoc := etree.NewDocument()
	trzbaDoc.SetRoot(trzbaElem)

	trzbaBytes, err := trzbaDoc.WriteToBytes()
	require.NoError(t, err, "write trzba element from the generated envelope back to bytes")

	var trzbaReversed *eet.TrzbaType
	err = xml.Unmarshal(trzbaBytes, &trzbaReversed)
	require.NoError(t, err, "unmarshal generated envelope back to the TrzbaType")

	require.EqualValues(t, trzba, trzbaReversed)
}

func BenchmarkNewSoapEnvelope(b *testing.B) {
	var trzba = &eet.TrzbaType{
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
	}

	rawCrt := readFile(b, "testdata/EET_CA1_Playground-CZ00000019.crt")
	pemCrt, _ := pem.Decode(rawCrt)
	crt, err := wsse.ParseCertificate(pemCrt)
	require.NoError(b, err, "parse ssl certificate")

	rawPk := readFile(b, "testdata/EET_CA1_Playground-CZ00000019.key")
	pemPk, _ := pem.Decode(rawPk)
	pk, err := wsse.ParsePrivateKey(pemPk)
	require.NoError(b, err, "parse private key")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eet.NewTrzbaEnvelope(trzba, crt, pk)
	}
}
