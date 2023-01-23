/*
Copyright 2020 The cert-manager Authors.

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

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// Copied from x509.go
var (
	OIDExtensionBasicConstraints = []int{2, 5, 29, 19}
)

// Copied from x509.go
type basicConstraints struct {
	IsCA bool
}

// Adapted from x509.go
func MarshalBasicConstraints(isCA bool) (pkix.Extension, error) {
	ext := pkix.Extension{Id: OIDExtensionBasicConstraints}

	var err error
	ext.Value, err = asn1.Marshal(basicConstraints{isCA})
	return ext, err
}
