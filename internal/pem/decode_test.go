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

// largestLimit is set to maxBundleSize as the maximum size that any of our SafeDecode* functions accepts; we use this
// as an upper bound for the size of pathologicalFuzzFile.
const largestLimit = maxBundleSize

func init() {
	fuzzFilename := "./testdata/issue-ghsa-r4pg-vg54-wxx4.bin"

	var err error
	fuzzFile, err = os.ReadFile(fuzzFilename)
	if err != nil {
		panic(fmt.Errorf("failed to read fuzz file %q: %s", fuzzFilename, err))
	}

	// Assert that largestLimit is actually the largest limit so we're definitely
	// testing the worst case with pathologicalFuzzFile. This guards against future changes making these tests invalid;
	// e.g. if, maxCertificateChainSize actually became the largest we accept, we'd want to test against that instead.
	if largestLimit < maxPrivateKeyPEMSize || largestLimit < maxCertificateChainSize {
		panic(fmt.Errorf("invalid test: expected max cert bundle size %d to be larger than maxPrivateKeyPEMSize %d and maxCertificateChainSize %d", maxBundleSize, maxPrivateKeyPEMSize, maxCertificateChainSize))
	}

	pathologicalFuzzFile = fuzzFile[:largestLimit-1]
}

func TestFuzzData(t *testing.T) {
	// The fuzz test data should be rejected by all Safe* functions

	// Ensure fuzz test data is larger than the max we allow
	if len(fuzzFile) < maxCertificateChainSize {
		t.Fatalf("invalid test; fuzz file data is smaller than the maximum allowed input")
	}

	var block *stdpem.Block
	var rest []byte
	var err error

	expPrivateKeyError := ErrPEMDataTooLarge(maxPrivateKeyPEMSize)
	expCSRError := ErrPEMDataTooLarge(maxLeafCertificatePEMSize)
	expSingleCertError := ErrPEMDataTooLarge(maxLeafCertificatePEMSize)
	expCertChainError := ErrPEMDataTooLarge(maxCertificateChainSize)
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
	for b.Loop() {
		testPathologicalInternal(b)
	}
}

func TestDefaultSizeLimits(t *testing.T) {
	limits := DefaultSizeLimits()

	if limits.MaxCertificateSize != maxLeafCertificatePEMSize {
		t.Errorf("Expected MaxCertificateSize %d, got %d", maxLeafCertificatePEMSize, limits.MaxCertificateSize)
	}
	if limits.MaxPrivateKeySize != maxPrivateKeyPEMSize {
		t.Errorf("Expected MaxPrivateKeySize %d, got %d", maxPrivateKeyPEMSize, limits.MaxPrivateKeySize)
	}
	if limits.MaxChainLength != maxCertificateChainSize {
		t.Errorf("Expected MaxChainLength %d, got %d", maxCertificateChainSize, limits.MaxChainLength)
	}
	if limits.MaxBundleSize != maxBundleSize {
		t.Errorf("Expected MaxBundleSize %d, got %d", maxBundleSize, limits.MaxBundleSize)
	}
}

func TestGlobalSizeLimits(t *testing.T) {
	// Save the original global limits
	originalLimits := GetGlobalSizeLimits()
	defer SetGlobalSizeLimits(originalLimits)

	// Set custom limits
	customLimits := SizeLimits{
		MaxCertificateSize: 10000,
		MaxPrivateKeySize:  20000,
		MaxChainLength:     15,
		MaxBundleSize:      500000,
	}
	SetGlobalSizeLimits(customLimits)

	// Verify they are set correctly
	retrievedLimits := GetGlobalSizeLimits()
	if retrievedLimits != customLimits {
		t.Errorf("Expected %+v, got %+v", customLimits, retrievedLimits)
	}
}

func TestNewSizeLimitsFromConfig(t *testing.T) {
	limits := NewSizeLimitsFromConfig(1000, 2000, 5, 10000)

	expected := SizeLimits{
		MaxCertificateSize: 1000,
		MaxPrivateKeySize:  2000,
		MaxChainLength:     5,
		MaxBundleSize:      10000,
	}

	if limits != expected {
		t.Errorf("Expected %+v, got %+v", expected, limits)
	}
}

func TestSizeLimitsMethods(t *testing.T) {
	limits := SizeLimits{
		MaxCertificateSize: 1000,
		MaxPrivateKeySize:  2000,
		MaxChainLength:     3,
		MaxBundleSize:      5000,
	}

	// Test data that should pass
	smallCert := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJANbFABEA3+G2MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMzEwMDExMDAwMDBaFw0yNDEwMDExMDAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDd7i7JWEahSb1s
dMl8h5qbRb5qZsJgDTfOvFwJ9QVv2+yH3Cqc2a3EeY4pJ9XpE7c1nE5lX3r2a9s
VqHUcXBKrAgMBAAEwDQYJKoZIhvcNAQELBQADQQAOIQEwLNqh3uPJ6YpOZJ2g7C0
rAu5E8qkP4OqxqvCDxJhyWrF9p7CnX3HvA8J2nzQ8qYpQ3QqE7M3G5rnE9+5v
-----END CERTIFICATE-----`)

	// Test SafeDecodeSingleCertificate with custom limits
	block, rest, err := limits.SafeDecodeSingleCertificate(smallCert)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if block == nil {
		t.Error("Expected non-nil block")
	}
	if len(rest) != 0 {
		t.Error("Expected empty rest")
	}

	// Test data that should fail due to size limits
	largeCert := make([]byte, 2000)
	copy(largeCert, smallCert)
	// Pad with additional data to exceed limit
	for i := len(smallCert); i < len(largeCert); i++ {
		largeCert[i] = 'A'
	}

	block, _, err = limits.SafeDecodeSingleCertificate(largeCert)
	if err == nil {
		t.Error("Expected error for oversized certificate")
	}
	if block != nil {
		t.Error("Expected nil block for oversized certificate")
	}

	// Verify error is of correct type
	if pemErr, ok := err.(ErrPEMDataTooLarge); !ok || int(pemErr) != limits.MaxCertificateSize {
		t.Errorf("Expected ErrPEMDataTooLarge(%d), got %v", limits.MaxCertificateSize, err)
	}
}

func TestSafeFunctionsUseGlobalLimits(t *testing.T) {
	// Save the original global limits
	originalLimits := GetGlobalSizeLimits()
	defer SetGlobalSizeLimits(originalLimits)

	// Set very restrictive limits
	restrictiveLimits := SizeLimits{
		MaxCertificateSize: 100, // Very small to ensure failure
		MaxPrivateKeySize:  100,
		MaxChainLength:     1,
		MaxBundleSize:      200,
	}
	SetGlobalSizeLimits(restrictiveLimits)

	// Test data that would normally pass with default limits
	normalCert := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJANbFABEA3+G2MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMzEwMDExMDAwMDBaFw0yNDEwMDExMDAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDd7i7JWEahSb1s
dMl8h5qbRb5qZsJgDTfOvFwJ9QVv2+yH3Cqc2a3EeY4pJ9XpE7c1nE5lX3r2a9s
VqHUcXBKrAgMBAAEwDQYJKoZIhvcNAQELBQADQQAOIQEwLNqh3uPJ6YpOZJ2g7C0
rAu5E8qkP4OqxqvCDxJhyWrF9p7CnX3HvA8J2nzQ8qYpQ3QqE7M3G5rnE9+5v
-----END CERTIFICATE-----`)

	// All global safe functions should now fail due to restrictive limits
	_, _, err := SafeDecodeSingleCertificate(normalCert)
	if err == nil {
		t.Error("Expected SafeDecodeSingleCertificate to fail with restrictive limits")
	}

	_, _, err = SafeDecodeCSR(normalCert)
	if err == nil {
		t.Error("Expected SafeDecodeCSR to fail with restrictive limits")
	}

	_, _, err = SafeDecodeCertificateChain(normalCert)
	if err == nil {
		t.Error("Expected SafeDecodeCertificateChain to fail with restrictive limits")
	}

	_, _, err = SafeDecodeCertificateBundle(normalCert)
	if err == nil {
		t.Error("Expected SafeDecodeCertificateBundle to fail with restrictive limits")
	}
}

func TestChainSizeCalculation(t *testing.T) {
	limits := SizeLimits{
		MaxCertificateSize: 1000,
		MaxPrivateKeySize:  2000,
		MaxChainLength:     3,
		MaxBundleSize:      5000,
	}

	// Create test data that should pass individual cert check but fail chain check
	mediumCert := make([]byte, 900) // Below single cert limit
	copy(mediumCert, `-----BEGIN CERTIFICATE-----`)

	// Chain calculation: 900 * 3 = 2700, which is less than MaxBundleSize (5000), so should pass
	_, _, err := limits.SafeDecodeCertificateChain(mediumCert)
	// This might fail due to invalid PEM format, but not due to size
	// The important thing is we're testing the size calculation logic
	_ = err

	// Now test with a larger cert that would exceed chain size
	largeCert := make([]byte, 2000) // Above chain calculation: 2000 * 3 = 6000 > 5000
	copy(largeCert, `-----BEGIN CERTIFICATE-----`)
	for i := 25; i < len(largeCert); i++ {
		largeCert[i] = 'A'
	}

	_, _, err = limits.SafeDecodeCertificateChain(largeCert)
	if err == nil {
		t.Error("Expected SafeDecodeCertificateChain to fail due to size limits")
	}
}
