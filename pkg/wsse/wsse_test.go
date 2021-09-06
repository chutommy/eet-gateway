package wsse_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func readFile(t *testing.T, filepath string) []byte {
	t.Helper()
	raw, err := ioutil.ReadFile(filepath)
	require.NoError(t, err, "read file")
	return raw
}
