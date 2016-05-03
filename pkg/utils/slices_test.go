package utils_test

import (
	"sort"
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
	output := utils.StringSliceDistinct([]string{"abc", "def", "def"})
	expected := []string{"abc", "def"}

	sort.Strings(output)
	sort.Strings(expected)

	assert.Equal(
		t,
		expected,
		output,
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
		"e80b5017098950fc58aad83c8c14978e",
		utils.HashStringSlice([]string{"abc", "def"}),
	)
	assert.Equal(
		t,
		utils.HashStringSlice([]string{"def", "abc"}),
		utils.HashStringSlice([]string{"abc", "def"}),
	)
	assert.NotEqual(
		t,
		utils.HashStringSlice([]string{"123"}),
		utils.HashStringSlice([]string{"abc", "def"}),
	)
}
