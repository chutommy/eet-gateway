package ca_test

import (
	"testing"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/stretchr/testify/require"
)

func TestRoots(t *testing.T) {
	prodRoots, err := ca.ProductionRoots()
	require.NoError(t, err)
	require.NotEmpty(t, prodRoots)

	pgRoots, err := ca.PlaygroundRoots()
	require.NoError(t, err)
	require.NotEmpty(t, pgRoots)
}
