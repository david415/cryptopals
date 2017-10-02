package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStuff(t *testing.T) {
	require := require.New(t)

	fu := "7~8Yh,;g"
	truthy := ContainsNonASCII(fu)
	require.True(truthy, "should be true")
}
