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

// Package pem provides utility functions for safely decoding PEM data, placing upper limits on the size
// of data that will be processed. It functions as an extension to the standard library "encoding/pem" functions.
package pem

import (
	stdpem "encoding/pem"
	"errors"
	"fmt"
)

// The constants below are estimates at reasonable upper bounds for sizes of PEM data that cert-manager might encounter.
// cert-manager supports RSA, ECDSA and Ed25519 keys, of which RSA keys are by far the largest.

// We'll aim to support RSA certs / keys which are larger than the maximum size (defined in pkg/util/pki.MaxRSAKeySize).

// RSA keys grow proportional to the size of the RSA key used. For example:
// PEM-encoded RSA Keys: 4096-bit is ~3kB, 8192-bit is ~6kB and a 16k-bit key is ~12kB.

// Certificates have two variables; the public key of the cert, and the signature from the signing cert.
// An N-bit key produces an N-byte signature, so as a worst case for us, a 16kB RSA key will create a 2kB signature.

// PEM-encoded RSA X.509 certificates:
// Signed with  1k-bit RSA key: 4096-bit is ~1.4kB, 8192-bit is ~2kB, 16k-bit is ~3.5kB
// Signed with 16k-bit RSA key: 4096-bit is ~3.3kB, 8192-bit is ~4kB, 16k-bit is ~5.4kB

// See https://fm4dd.com/openssl/certexamples.shtm for examples of large RSA certs / keys

const (
	// maxCertificatePEMSize is the maximum size, in bytes, of a single PEM-encoded X.509 certificate which SafeDecodeSingleCertificate will accept.
	// The value is based on how large a "realistic" (but still very large) self-signed 16k-bit RSA certficate might be.
	// 16k-bit RSA keys are impractical on most on modern hardware due to how slow they can be,
	// so we can reasonably assume that no real-world PEM-encoded X.509 cert will be this large.
	// Note that X.509 certificates can contain extra abitrary data (e.g. DNS names, policy names, etc) whose size is hard to predict.
	// So we guess at how much of that data we'll allow in very large certs and allow about 1kB of such data.
	maxCertificatePEMSize = 6500

	// maxPrivateKeyPEMSize is the maximum size, in bytes, of PEM-encoded private keys which SafeDecodePrivateKey will accept.
	// cert-manager supports RSA, ECDSA and Ed25519 keys, of which RSA is by far the largest.
	// The value is based on how large a "realistic" (but very large) 16k-bit RSA private key might be.
	// Given that 16k-bit RSA keys are so slow to use as to be impractical on modern hardware,
	// we can reasonably assume that no real-world PEM-encoded key will be this large.
	maxPrivateKeyPEMSize = 13000

	// maxChainSize is the maximum number of 16k-bit RSA certificates signed by 16k-bit RSA CAs we'll allow in a given call to SafeDecodeMultipleCertificates.
	// This is _not_ the maximum number of certificates cert-manager will process in a given chain, which could be much larger.
	// This is simply the maximum number of worst-case certificates we'll accept in a chain.
	maxChainSize = 10
)

var (
	// ErrNoPEMData is returned when the given data contained no PEM
	ErrNoPEMData = errors.New("no PEM data was found in given input")
)

// ErrPEMDataTooLarge is returned when the given data is larger than the maximum allowed
type ErrPEMDataTooLarge int

// Error returns an error string
func (e ErrPEMDataTooLarge) Error() string {
	return fmt.Sprintf("provided PEM data was larger than the maximum %dB", int(e))
}

func safeDecodeInternal(b []byte, maxSize int) (*stdpem.Block, []byte, error) {
	if len(b) > maxSize {
		return nil, b, ErrPEMDataTooLarge(maxSize)
	}

	block, rest := stdpem.Decode(b)
	if block == nil {
		return nil, rest, ErrNoPEMData
	}

	return block, rest, nil
}

// SafeDecodePrivateKey calls [encoding/pem.Decode] on the given input as long as it's within a sensible range for
// how large we expect a private key to be. The baseline is a 16k-bit RSA private key, which is larger than the maximum
// supported by cert-manager for key generation.
func SafeDecodePrivateKey(b []byte) (*stdpem.Block, []byte, error) {
	return safeDecodeInternal(b, maxPrivateKeyPEMSize)
}

// SafeDecodeCSR calls [encoding/pem.Decode] on the given input as long as it's within a sensible range for
// how large we expect a single PEM-encoded PKCS#10 CSR to be.
// We assume that a PKCS#12 CSR is smaller than a single certificate because our assumptions are that
// a certificate has a large public key and a large signature, which is roughly the case for a CSR.
// We also assume that we'd only ever decode one CSR which is the case in practice.
func SafeDecodeCSR(b []byte) (*stdpem.Block, []byte, error) {
	return safeDecodeInternal(b, maxCertificatePEMSize)
}

// SafeDecodeSingleCertificate calls [encoding/pem.Decode] on the given input as long as it's within a sensible range for
// how large we expect a single PEM-encoded X.509 certificate to be.
// The baseline is a 16k-bit RSA certificate signed by a different 16k-bit RSA CA, which is larger than the maximum
// supported by cert-manager for key generation.
func SafeDecodeSingleCertificate(b []byte) (*stdpem.Block, []byte, error) {
	return safeDecodeInternal(b, maxCertificatePEMSize)
}

// SafeDecodeMultipleCertificates calls [encoding/pem.Decode] on the given input as long as it's within a sensible range for
// how large we expect a reasonable-length PEM-encoded X.509 certificate chain to be.
// The baseline is several 16k-bit RSA certificates, all signed by 16k-bit RSA keys, which is larger than the maximum
// supported by cert-manager for key generation.
// The maximum number of chains supported by this function is not reflective of the maximum chain length supported by
// cert-manager; a larger chain of smaller certificate should be supported.
func SafeDecodeMultipleCertificates(b []byte) (*stdpem.Block, []byte, error) {
	return safeDecodeInternal(b, maxCertificatePEMSize*maxChainSize)
}
