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

package matcher

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"reflect"
	"sort"

	"github.com/onsi/gomega/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func HaveSameSANsAs(certWithExpectedSAN string) types.GomegaMatcher {
	return SANEquals(extractSANsFromCertificate(certWithExpectedSAN))
}

// HaveSans will check that the PEM of the certificates
func SANEquals(sanExtensionExpected interface{}) *SANMatcher {
	extension, ok := sanExtensionExpected.(pkix.Extension)
	if !ok || !extension.Id.Equal(oidExtensionSubjectAltName) {
		Fail("Invalid use of the SANEquals matcher, please supply a valid SAN pkix.Extension")
	}
	return &SANMatcher{
		SANExtensionExpected: extension,
	}
}

type SANMatcher struct {
	SANExtensionExpected pkix.Extension
}

// Comparing pkix.Extensions obtained from an expected pkix.Extension
func (s *SANMatcher) Match(actual interface{}) (success bool, err error) {
	actualExtensions, ok := actual.([]pkix.Extension)
	if !ok {
		return false, fmt.Errorf("Invalid use of the SANEquals matcher, please supply a valid SAN pkix.Extension")
	}

	var actualSANExtension pkix.Extension
	var SANfound bool
	for _, extension := range actualExtensions {
		if extension.Id.Equal(oidExtensionSubjectAltName) {
			actualSANExtension = extension
			SANfound = true
		}
	}

	if !SANfound {
		return false, fmt.Errorf("The supplied Extensions does not contain a SAN extension, got: %v", actualExtensions)
	}

	var actualGeneralNames []asn1.RawValue
	rest, err := asn1.Unmarshal(actualSANExtension.Value, &actualGeneralNames)
	if err != nil {
		return false, err
	} else if len(rest) != 0 {
		return false, fmt.Errorf("x509: trailing data after X.509 extension")
	}

	var expectedGeneralNames []asn1.RawValue
	rest, err = asn1.Unmarshal(s.SANExtensionExpected.Value, &expectedGeneralNames)
	if err != nil {
		return false, err
	} else if len(rest) != 0 {
		return false, fmt.Errorf("x509: trailing data after X.509 extension")
	}

	sortGeneralNamesByTagBytes(actualGeneralNames)
	sortGeneralNamesByTagBytes(expectedGeneralNames)

	return reflect.DeepEqual(actualGeneralNames, expectedGeneralNames), nil

}

// TODO tested manually with same SAN, same type with different ordering successfully
// we should still add unit tests in future as it's a non trivial matcher
func sortGeneralNamesByTagBytes(generalNames []asn1.RawValue) {

	sort.Slice(generalNames, func(i, j int) bool {
		if generalNames[i].Tag < generalNames[j].Tag {
			return true
		}
		if generalNames[i].Tag == generalNames[j].Tag {
			// we compare the stringified base64 encoding of the bytes to ensure a different ordering when the
			// same SAN type is used twice

			return base64.StdEncoding.EncodeToString(generalNames[i].Bytes) < base64.StdEncoding.EncodeToString(generalNames[j].Bytes)
		}
		return false
	})

}

func (s *SANMatcher) FailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Supplied SAN did not match the expected SAN (even disregarding ordering).\n Actual: %v\nExpected:%v", actual, s.SANExtensionExpected)
}

func (s *SANMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return fmt.Sprintf("Supplied SAN  matched the expected SAN (modulo ordering) which was not expected.\n Actual: %v\nExpected: %v", actual, s.SANExtensionExpected)

}

var oidExtensionSubjectAltName = []int{2, 5, 29, 17}

func extractSANsFromCertificate(certDER string) pkix.Extension {
	block, rest := pem.Decode([]byte(certDER))
	Expect(rest).To(BeEmpty())

	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())

	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oidExtensionSubjectAltName) {
			return extension
		}
	}

	Fail("Could not find SANs in certificate")
	return pkix.Extension{}
}
