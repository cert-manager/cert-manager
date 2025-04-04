/*
Copyright 2024 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pem

import (
	stdpem "encoding/pem"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

// fuzzFile is a fuzz-test-generated file which causes significant slowdown when passed to
// the standard library pem.Decode function. It's used as a test case to ensure that our
// safe PEM decoding functions reject it.
var fuzzFile []byte

// pathologicalFuzzFile is a copy of fuzzFile trimmed to fit inside our max allowable size
var pathologicalFuzzFile []byte

func init() {
	fuzzFilename := "./testdata/issue-ghsa-r4pg-vg54-wxx4.bin"

	var err error
	fuzzFile, err = os.ReadFile(fuzzFilename)
	if err != nil {
		panic(fmt.Errorf("failed to read fuzz file %q: %s", fuzzFilename, err))
	}

	// Assert that SafeDecodeCertificateBundle has the largest max size so we're definitely
	// testing the worst case with pathologicalFuzzFile
	if maxBundleSize < maxPrivateKeyPEMSize || maxBundleSize < maxChainSize {
		panic(fmt.Errorf("invalid test: expected max cert bundle size %d to be larger than maxPrivateKeyPEMSize %d", maxChainSize, maxPrivateKeyPEMSize))
	}

	pathologicalFuzzFile = fuzzFile[:maxBundleSize-1]
}

func TestFuzzData(t *testing.T) {
	// The fuzz test data should be rejected by all Safe* functions

	// Ensure fuzz test data is larger than the max we allow
	if len(fuzzFile) < maxCertificatePEMSize*maxChainSize {
		t.Fatalf("invalid test; fuzz file data is smaller than the maximum allowed input")
	}

	var block *stdpem.Block
	var rest []byte
	var err error

	expPrivateKeyError := ErrPEMDataTooLarge(maxPrivateKeyPEMSize)
	expCSRError := ErrPEMDataTooLarge(maxCertificatePEMSize)
	expSingleCertError := ErrPEMDataTooLarge(maxCertificatePEMSize)
	expCertChainError := ErrPEMDataTooLarge(maxCertificatePEMSize * maxChainSize)
	expCertBundleError := ErrPEMDataTooLarge(maxBundleSize)

	block, rest, err = SafeDecodePrivateKey(fuzzFile)
	if err != expPrivateKeyError {
		t.Errorf("SafeDecodePrivateKey: wanted %s but got %v", expPrivateKeyError, err)
	}

	if block != nil {
		t.Errorf("SafeDecodePrivateKey: expected block to be nil")
	}

	if !slices.Equal(rest, fuzzFile) {
		t.Errorf("SafeDecodePrivateKey: expected rest to equal input")
	}

	block, rest, err = SafeDecodeCSR(fuzzFile)
	if err != expCSRError {
		t.Errorf("SafeDecodeCSR: wanted %s but got %v", expCSRError, err)
	}

	if block != nil {
		t.Errorf("SafeDecodeCSR: expected block to be nil")
	}

	if !slices.Equal(rest, fuzzFile) {
		t.Errorf("SafeDecodeCSR: expected rest to equal input")
	}

	block, rest, err = SafeDecodeSingleCertificate(fuzzFile)
	if err != expSingleCertError {
		t.Errorf("SafeDecodeSingleCertificate: wanted %s but got %v", expSingleCertError, err)
	}

	if block != nil {
		t.Errorf("SafeDecodeSingleCertificate: expected block to be nil")
	}

	if !slices.Equal(rest, fuzzFile) {
		t.Errorf("SafeDecodeSingleCertificate: expected rest to equal input")
	}

	block, rest, err = SafeDecodeCertificateChain(fuzzFile)
	if err != expCertChainError {
		t.Errorf("SafeDecodeCertificateChain: wanted %s but got %v", expCertChainError, err)
	}

	if block != nil {
		t.Errorf("SafeDecodeCertificateChain: expected block to be nil")
	}

	if !slices.Equal(rest, fuzzFile) {
		t.Errorf("SafeDecodeCertificateChain: expected rest to equal input")
	}

	block, rest, err = SafeDecodeCertificateBundle(fuzzFile)
	if err != expCertBundleError {
		t.Errorf("SafeDecodeCertificateBundle: wanted %s but got %v", expCertBundleError, err)
	}

	if block != nil {
		t.Errorf("SafeDecodeCertificateBundle: expected block to be nil")
	}

	if !slices.Equal(rest, fuzzFile) {
		t.Errorf("SafeDecodeCertificateBundle: expected rest to equal input")
	}
}

func testPathologicalInternal(t testing.TB) {
	block, rest, err := SafeDecodeCertificateBundle(pathologicalFuzzFile)

	if err != ErrNoPEMData {
		t.Errorf("pathological input: expected err %s but got %v", ErrNoPEMData, err)
	}

	if block != nil {
		t.Errorf("pathological input: expected block to be nil")
	}

	if !slices.Equal(rest, pathologicalFuzzFile) {
		t.Errorf("pathological input: expected rest to equal input")
	}
}

func TestPathologicalInput(t *testing.T) {
	// This test checks the runtime of the worst case scenario, so we can check it's not unacceptably
	// slow (indicating that our max sizes might be too permissive)
	beforeCall := time.Now()

	testPathologicalInternal(t)

	afterCall := time.Now()

	callDuration := afterCall.Sub(beforeCall)

	t.Logf("pathological input: took %s to execute", callDuration)
}

func BenchmarkPathologicalInput(b *testing.B) {
	for n := 0; n < b.N; n++ {
		testPathologicalInternal(b)
	}
}

// resetEnvironmentAndValues is a helper function to manage environment variables and package values
func resetEnvironmentAndValues(t *testing.T) func() {
	// Save original values
	origValues := map[string]int{
		"maxCertificatePEMSize": maxCertificatePEMSize,
		"maxPrivateKeyPEMSize":  maxPrivateKeyPEMSize,
		"maxChainSize":          maxChainSize,
		"maxCertsInTrustBundle": maxCertsInTrustBundle,
		"estimatedCACertSize":   estimatedCACertSize,
		"maxBundleSize":         maxBundleSize,
	}

	// Clear all environment variables
	os.Unsetenv(envMaxCertSize)
	os.Unsetenv(envMaxPrivateKeySize)
	os.Unsetenv(envMaxChainSize)
	os.Unsetenv(envMaxBundleCerts)
	os.Unsetenv(envEstimatedCertSize)

	// Return cleanup function
	return func() {
		maxCertificatePEMSize = origValues["maxCertificatePEMSize"]
		maxPrivateKeyPEMSize = origValues["maxPrivateKeyPEMSize"]
		maxChainSize = origValues["maxChainSize"]
		maxCertsInTrustBundle = origValues["maxCertsInTrustBundle"]
		estimatedCACertSize = origValues["estimatedCACertSize"]
		maxBundleSize = origValues["maxBundleSize"]
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue int
		want         int
	}{
		{
			name:         "no env var set",
			envKey:       "TEST_NONEXISTENT",
			defaultValue: 100,
			want:         100,
		},
		{
			name:         "valid env var",
			envKey:       "TEST_VALID",
			envValue:     "200",
			defaultValue: 100,
			want:         200,
		},
		{
			name:         "invalid env var",
			envKey:       "TEST_INVALID",
			envValue:     "not-a-number",
			defaultValue: 100,
			want:         100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv(tt.envKey, tt.envValue)
			}
			if got := getEnvInt(tt.envKey, tt.defaultValue); got != tt.want {
				t.Errorf("getEnvInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnvironmentOverrides(t *testing.T) {
	// Set test environment variables before reinitializing values
	t.Setenv(envMaxCertSize, "10000")
	t.Setenv(envMaxPrivateKeySize, "20000")
	t.Setenv(envMaxChainSize, "20")
	t.Setenv(envMaxBundleCerts, "200")
	t.Setenv(envEstimatedCertSize, "3000")

	// Reinitialize package variables with new environment values
	maxCertificatePEMSize = getEnvInt(envMaxCertSize, 6500)
	maxPrivateKeyPEMSize = getEnvInt(envMaxPrivateKeySize, 13000)
	maxChainSize = getEnvInt(envMaxChainSize, 10)
	maxCertsInTrustBundle = getEnvInt(envMaxBundleCerts, 150)
	estimatedCACertSize = getEnvInt(envEstimatedCertSize, 2200)
	maxBundleSize = maxCertsInTrustBundle * estimatedCACertSize

	// Save original values for restoration
	origValues := map[string]int{
		"maxCertificatePEMSize": maxCertificatePEMSize,
		"maxPrivateKeyPEMSize":  maxPrivateKeyPEMSize,
		"maxChainSize":          maxChainSize,
		"maxCertsInTrustBundle": maxCertsInTrustBundle,
		"estimatedCACertSize":   estimatedCACertSize,
		"maxBundleSize":         maxBundleSize,
	}

	// Restore original values after test
	defer func() {
		maxCertificatePEMSize = origValues["maxCertificatePEMSize"]
		maxPrivateKeyPEMSize = origValues["maxPrivateKeyPEMSize"]
		maxChainSize = origValues["maxChainSize"]
		maxCertsInTrustBundle = origValues["maxCertsInTrustBundle"]
		estimatedCACertSize = origValues["estimatedCACertSize"]
		maxBundleSize = origValues["maxBundleSize"]
	}()

	// Create large test data that would fail with default sizes but pass with new sizes
	largeKey := make([]byte, 15000)

	// Test that decode succeeds with new limits
	_, _, err := SafeDecodePrivateKey(largeKey)
	if err != ErrNoPEMData { // We expect ErrNoPEMData since our test data isn't valid PEM
		t.Errorf("Expected ErrNoPEMData for large key with increased limits, got: %v", err)
	}

	// Test that maxBundleSize is correctly derived
	expectedMaxBundleSize := 200 * 3000 // maxCertsInTrustBundle * estimatedCACertSize
	if maxBundleSize != expectedMaxBundleSize {
		t.Errorf("maxBundleSize = %d, want %d", maxBundleSize, expectedMaxBundleSize)
	}
}

func TestDefaultValues(t *testing.T) {
	cleanup := resetEnvironmentAndValues(t)
	defer cleanup()

	// Reinitialize package variables with cleared environment
	maxCertificatePEMSize = getEnvInt(envMaxCertSize, 6500)
	maxPrivateKeyPEMSize = getEnvInt(envMaxPrivateKeySize, 13000)
	maxChainSize = getEnvInt(envMaxChainSize, 10)
	maxCertsInTrustBundle = getEnvInt(envMaxBundleCerts, 150)
	estimatedCACertSize = getEnvInt(envEstimatedCertSize, 2200)
	maxBundleSize = maxCertsInTrustBundle * estimatedCACertSize

	// Expected default values
	expectedDefaults := map[string]int{
		"maxCertificatePEMSize": 6500,
		"maxPrivateKeyPEMSize":  13000,
		"maxChainSize":          10,
		"maxCertsInTrustBundle": 150,
		"estimatedCACertSize":   2200,
	}

	// Verify each default value
	if maxCertificatePEMSize != expectedDefaults["maxCertificatePEMSize"] {
		t.Errorf("maxCertificatePEMSize = %d, want %d", maxCertificatePEMSize, expectedDefaults["maxCertificatePEMSize"])
	}
	if maxPrivateKeyPEMSize != expectedDefaults["maxPrivateKeyPEMSize"] {
		t.Errorf("maxPrivateKeyPEMSize = %d, want %d", maxPrivateKeyPEMSize, expectedDefaults["maxPrivateKeyPEMSize"])
	}
	if maxChainSize != expectedDefaults["maxChainSize"] {
		t.Errorf("maxChainSize = %d, want %d", maxChainSize, expectedDefaults["maxChainSize"])
	}
	if maxCertsInTrustBundle != expectedDefaults["maxCertsInTrustBundle"] {
		t.Errorf("maxCertsInTrustBundle = %d, want %d", maxCertsInTrustBundle, expectedDefaults["maxCertsInTrustBundle"])
	}
	if estimatedCACertSize != expectedDefaults["estimatedCACertSize"] {
		t.Errorf("estimatedCACertSize = %d, want %d", estimatedCACertSize, expectedDefaults["estimatedCACertSize"])
	}

	// Verify derived value
	expectedMaxBundleSize := expectedDefaults["maxCertsInTrustBundle"] * expectedDefaults["estimatedCACertSize"]
	if maxBundleSize != expectedMaxBundleSize {
		t.Errorf("maxBundleSize = %d, want %d", maxBundleSize, expectedMaxBundleSize)
	}
}

func TestPartialEnvironmentOverride(t *testing.T) {
	cleanup := resetEnvironmentAndValues(t)
	defer cleanup()

	// Set only one environment variable
	t.Setenv(envMaxPrivateKeySize, "20000")

	// Reinitialize package variables
	maxCertificatePEMSize = getEnvInt(envMaxCertSize, 6500)
	maxPrivateKeyPEMSize = getEnvInt(envMaxPrivateKeySize, 13000)
	maxChainSize = getEnvInt(envMaxChainSize, 10)
	maxCertsInTrustBundle = getEnvInt(envMaxBundleCerts, 150)
	estimatedCACertSize = getEnvInt(envEstimatedCertSize, 2200)
	maxBundleSize = maxCertsInTrustBundle * estimatedCACertSize

	// Verify overridden value
	if maxPrivateKeyPEMSize != 20000 {
		t.Errorf("maxPrivateKeyPEMSize = %d, want 20000", maxPrivateKeyPEMSize)
	}

	// Verify other values remain at defaults
	if maxCertificatePEMSize != 6500 {
		t.Errorf("maxCertificatePEMSize = %d, want 6500", maxCertificatePEMSize)
	}
	if maxChainSize != 10 {
		t.Errorf("maxChainSize = %d, want 10", maxChainSize)
	}
	if maxCertsInTrustBundle != 150 {
		t.Errorf("maxCertsInTrustBundle = %d, want 150", maxCertsInTrustBundle)
	}
	if estimatedCACertSize != 2200 {
		t.Errorf("estimatedCACertSize = %d, want 2200", estimatedCACertSize)
	}

	// Verify derived value remains correct
	expectedMaxBundleSize := 150 * 2200
	if maxBundleSize != expectedMaxBundleSize {
		t.Errorf("maxBundleSize = %d, want %d", maxBundleSize, expectedMaxBundleSize)
	}
}
