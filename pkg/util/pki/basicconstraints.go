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
	"errors"
)

// Copied from x509.go
var (
	OIDExtensionBasicConstraints = []int{2, 5, 29, 19}
)

// Copied from x509.go
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// Adapted from x509.go
func MarshalBasicConstraints(isCA bool, maxPathLen *int) (pkix.Extension, error) {
	ext := pkix.Extension{Id: OIDExtensionBasicConstraints, Critical: true}

	// A value of -1 causes encoding/asn1 to omit the value as desired.
	maxPathLenValue := -1
	if maxPathLen != nil {
		maxPathLenValue = *maxPathLen
	}

	var err error
	ext.Value, err = asn1.Marshal(basicConstraints{isCA, maxPathLenValue})
	return ext, err
}

// Adapted from x509.go
func UnmarshalBasicConstraints(value []byte) (isCA bool, maxPathLen *int, err error) {
	var constraints basicConstraints
	var rest []byte

	if rest, err = asn1.Unmarshal(value, &constraints); err != nil {
		return isCA, maxPathLen, err
	} else if len(rest) != 0 {
		return isCA, maxPathLen, errors.New("x509: trailing data after X.509 BasicConstraints")
	}

	isCA = constraints.IsCA
	if constraints.MaxPathLen >= 0 {
		maxPathLen = new(int)
		*maxPathLen = constraints.MaxPathLen
	}
	return isCA, maxPathLen, nil
}
