package tester_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xenolf/lego/platform/tester"
)

var (
	envNamespace = "LEGO_TEST_"
	envVar01     = envNamespace + "01"
	envVar02     = envNamespace + "02"
	envVarDomain = envNamespace + "DOMAIN"
)

func TestMain(m *testing.M) {
	exitCode := m.Run()
	clearEnv()
	os.Exit(exitCode)
}

func applyEnv(envVars map[string]string) {
	for key, value := range envVars {
		if len(value) == 0 {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, value)
		}
	}
}

func clearEnv() {
	environ := os.Environ()
	for _, key := range environ {
		if strings.HasPrefix(key, envNamespace) {
			os.Unsetenv(strings.Split(key, "=")[0])
		}
	}
	os.Unsetenv("EXTRA_LEGO_TEST")
}

func TestEnvTest(t *testing.T) {
	testCases := []struct {
		desc         string
		envVars      map[string]string
		envTestSetup func() *tester.EnvTest
		expected     func(t *testing.T, envTest *tester.EnvTest)
	}{
		{
			desc: "simple",
			envVars: map[string]string{
				envVar01: "A",
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.True(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "missing env var",
			envVars: map[string]string{
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.False(t, envTest.IsLiveTest())
				assert.Equal(t, "", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithDomain",
			envVars: map[string]string{
				envVar01:     "A",
				envVar02:     "B",
				envVarDomain: "D",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).WithDomain(envVarDomain)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.True(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetValue(envVarDomain))
				assert.Equal(t, "D", envTest.GetDomain())
			},
		},
		{
			desc: "WithDomain missing env var",
			envVars: map[string]string{
				envVar01:     "A",
				envVarDomain: "D",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).WithDomain(envVarDomain)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.False(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetValue(envVarDomain))
				assert.Equal(t, "D", envTest.GetDomain())
			},
		},
		{
			desc: "WithDomain missing domain",
			envVars: map[string]string{
				envVar01: "A",
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).WithDomain(envVarDomain)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.False(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetValue(envVarDomain))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestRequirements",
			envVars: map[string]string{
				envVar01: "A",
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).WithLiveTestRequirements(envVar02)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.True(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestRequirements non required var missing",
			envVars: map[string]string{
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).WithLiveTestRequirements(envVar02)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.True(t, envTest.IsLiveTest())
				assert.Equal(t, "", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestRequirements required var missing",
			envVars: map[string]string{
				envVar01: "A",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).WithLiveTestRequirements(envVar02)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.False(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestRequirements WithDomain",
			envVars: map[string]string{
				envVar01:     "A",
				envVar02:     "B",
				envVarDomain: "D",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).
					WithDomain(envVarDomain).
					WithLiveTestRequirements(envVar02)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.True(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetValue(envVarDomain))
				assert.Equal(t, "D", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestRequirements WithDomain without domain",
			envVars: map[string]string{
				envVar01: "A",
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).
					WithDomain(envVarDomain).
					WithLiveTestRequirements(envVar02)
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.True(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetValue(envVarDomain))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestExtra true",
			envVars: map[string]string{
				envVar01: "A",
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).
					WithLiveTestExtra(func() bool { return true })
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.True(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestExtra false",
			envVars: map[string]string{
				envVar01: "A",
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).
					WithLiveTestExtra(func() bool { return false })
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.False(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestRequirements WithLiveTestExtra true",
			envVars: map[string]string{
				envVar01: "A",
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).
					WithLiveTestRequirements(envVar02).
					WithLiveTestExtra(func() bool { return true })
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.True(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestRequirements WithLiveTestExtra false",
			envVars: map[string]string{
				envVar01: "A",
				envVar02: "B",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).
					WithLiveTestRequirements(envVar02).
					WithLiveTestExtra(func() bool { return false })
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.False(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "B", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
		{
			desc: "WithLiveTestRequirements require env var missing WithLiveTestExtra true",
			envVars: map[string]string{
				envVar01: "A",
			},
			envTestSetup: func() *tester.EnvTest {
				return tester.NewEnvTest(envVar01, envVar02).
					WithLiveTestRequirements(envVar02).
					WithLiveTestExtra(func() bool { return true })
			},
			expected: func(t *testing.T, envTest *tester.EnvTest) {
				assert.False(t, envTest.IsLiveTest())
				assert.Equal(t, "A", envTest.GetValue(envVar01))
				assert.Equal(t, "", envTest.GetValue(envVar02))
				assert.Equal(t, "", envTest.GetDomain())
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer clearEnv()
			applyEnv(test.envVars)

			envTest := test.envTestSetup()

			test.expected(t, envTest)
		})
	}
}

func TestEnvTest_RestoreEnv(t *testing.T) {
	os.Setenv(envVar01, "A")
	os.Setenv(envVar02, "B")

	envTest := tester.NewEnvTest(envVar01, envVar02)

	clearEnv()

	envTest.RestoreEnv()

	assert.Equal(t, "A", os.Getenv(envVar01))
	assert.Equal(t, "B", os.Getenv(envVar02))
}

func TestEnvTest_ClearEnv(t *testing.T) {
	os.Setenv(envVar01, "A")
	os.Setenv(envVar02, "B")
	os.Setenv("EXTRA_LEGO_TEST", "X")

	envTest := tester.NewEnvTest(envVar01, envVar02)

	envTest.ClearEnv()

	assert.Equal(t, "", os.Getenv(envVar01))
	assert.Equal(t, "", os.Getenv(envVar02))
	assert.Equal(t, "X", os.Getenv("EXTRA_LEGO_TEST"))
}
