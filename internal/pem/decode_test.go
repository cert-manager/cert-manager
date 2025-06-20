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
	for range b.N {
		testPathologicalInternal(b)
	}
}
