package wsse_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

var certFiles = []struct {
	path string
}{
	{"testdata/EET_CA1_Playground-CZ00000019.crt"},
	{"testdata/EET_CA1_Playground-CZ683555118.crt"},
	{"testdata/EET_CA1_Playground-CZ1212121218.crt"},
}

func TestCertificate(t *testing.T) {
	for _, cf := range certFiles {
		t.Run(cf.path, func(t *testing.T) {
			raw := readFile(t, cf.path)

			p, _ := pem.Decode(raw)
			c, err := wsse.ParseCertificate(p)
			require.NoError(t, err, "parse SSL certificate")
			require.Equal(t, string(p.Bytes), string(c.Raw), "DER form of he same certificate")

			bin, err := wsse.CertificateToB64(c)
			require.NoError(t, err, "encode certificate to base64")

			validateB64Certificate(t, bin, c)
		})
	}
}

func validateB64Certificate(t *testing.T, bin []byte, c *x509.Certificate) {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(string(bin))
	require.NoError(t, err, "decode certificate to raw")
	require.Equal(t, c.Raw, decoded, "verify reversed encoded base64")
}

func BenchmarkParseCertificate(b *testing.B) {
	raw := readFile(b, "testdata/EET_CA1_Playground-CZ00000019.crt")
	pb, _ := pem.Decode(raw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = wsse.ParseCertificate(pb)
	}
}

func BenchmarkCertificateToB64(b *testing.B) {
	raw := readFile(b, "testdata/EET_CA1_Playground-CZ00000019.crt")
	pb, _ := pem.Decode(raw)
	crt, err := wsse.ParseCertificate(pb)
	require.NoError(b, err, "parse SSL certificate")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = wsse.CertificateToB64(crt)
	}
}

var pkFiles = []struct {
	path string
}{
	{"testdata/EET_CA1_Playground-CZ00000019.key"},
	{"testdata/EET_CA1_Playground-CZ683555118.key"},
	{"testdata/EET_CA1_Playground-CZ1212121218.key"},
}

func TestPrivateKey(t *testing.T) {
	for _, tc := range pkFiles {
		t.Run(tc.path, func(t *testing.T) {
			raw := readFile(t, tc.path)
			pkPB, _ := pem.Decode(raw)
			pk, err := wsse.ParsePrivateKey(pkPB)
			require.NoError(t, err, "parse private key: %w", err)
			require.NoError(t, pk.Validate(), "valid private key")
		})
	}
}

func BenchmarkParsePrivateKey(b *testing.B) {
	raw := readFile(b, "testdata/EET_CA1_Playground-CZ00000019.key")
	pkPB, _ := pem.Decode(raw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = wsse.ParsePrivateKey(pkPB)
	}
}
