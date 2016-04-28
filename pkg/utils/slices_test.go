package utils_test

import (
	"testing"

	"github.com/simonswine/kube-lego/pkg/utils"

	"github.com/stretchr/testify/assert"
)

func TestStringSliceLowerCase(t *testing.T) {
	assert.Equal(
		t,
		[]string{"abc", "def"},
		utils.StringSliceLowerCase([]string{"AbC", "def"}),
	)
	assert.Equal(
		t,
		[]string{"abc", "def", "def"},
		utils.StringSliceLowerCase([]string{"abc", "def", "def"}),
	)
}

func TestStringSliceDistinct(t *testing.T) {
	assert.Equal(
		t,
		[]string{"abc", "def"},
		utils.StringSliceDistinct([]string{"abc", "def"}),
	)
	assert.Equal(
		t,
		[]string{"abc", "def"},
		utils.StringSliceDistinct([]string{"abc", "def", "def"}),
	)
	assert.Equal(
		t,
		[]string{},
		utils.StringSliceDistinct([]string{}),
	)
}

func TestHashStringSlice(t *testing.T) {
	assert.Equal(
		t,
		"d41d8cd98f00b204e9800998ecf8427e",
		utils.HashStringSlice([]string{"abc", "def"}),
	)
	assert.Equal(
		t,
		utils.HashStringSlice([]string{"def", "abc"}),
		utils.HashStringSlice([]string{"abc", "def"}),
	)
}
