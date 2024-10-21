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

// Package cmrand provides cryptographically secure random number generation utilities for use in
// cert-manager code. The default RNG source in this package is `crypto/rand`, which is suitable for
// most use-cases, but can be configured if desired.
// WARNING: Cryptographically secure RNG is critical for secure operation of cert-manager. Don't
// change the RNG unless you're certain you know what you're doing.
package cmrand

import (
	"crypto/rand"
	"io"
	"math/big"
)

// Reader is a centralized point of configuration for random number generation across cert-manager.
// It defaults to pointing at `crypto/rand.Reader`.
// A custom / hardware RNG can be configured globally instead by changing this variable on startup.
var Reader io.Reader = rand.Reader

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// SerialNumber returns a random serial number suitable for use in an X.509 certificate.
// This function may change the size of serial number it generates between versions of cert-manager;
// do not rely on SerialNumber to return a constant-sized number.
func SerialNumber() (*big.Int, error) {
	return rand.Int(Reader, serialNumberLimit)
}
