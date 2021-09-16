package eet_test

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/stretchr/testify/require"
)

func readFile(t require.TestingT, path string) []byte {
	raw, err := ioutil.ReadFile(path)
	require.NoError(t, err, "read file")

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
