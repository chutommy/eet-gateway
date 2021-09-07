package wsse_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	raw, err := ioutil.ReadFile(path)
	require.NoError(t, err, "read file")

	return raw
}

func readFileB(b *testing.B, path string) []byte {
	b.Helper()

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		b.Fatalf("read file: %w", err)
	}

	return raw
}
