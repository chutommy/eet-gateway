package wsse_test

import (
	"io/ioutil"

	"github.com/stretchr/testify/require"
)

func readFile(t require.TestingT, path string) []byte {
	raw, err := ioutil.ReadFile(path)
	require.NoError(t, err, "read file")

	return raw
}
