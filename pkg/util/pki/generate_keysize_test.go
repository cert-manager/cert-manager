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

package pki

import "testing"

func TestMaxRSAKeySizeSanity(t *testing.T) {
	// This test ensures that if we bump our max RSA key size in the future, someone will come and
	// re-check our assumptions about max PEM sizes.
	if MaxRSAKeySize > 8192 {
		t.Fatalf("MaxRSAKeySize has been increased which may invalidate the assumptions for safe PEM decoding in internal/pem/*.go\nCheck the max sizes and change this test once complete!")
	}
}
