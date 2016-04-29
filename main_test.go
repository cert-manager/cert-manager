package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVesion(t *testing.T) {
	assert.Equal(t, "unknown", Version())
}
