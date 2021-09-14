package wsse_test

import (
	"encoding/pem"
	"testing"

	"github.com/chutommy/eetgateway/pkg/wsse"
	"github.com/stretchr/testify/require"
)

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
