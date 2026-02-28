/*
Copyright 2025 The cert-manager Authors.

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
	"crypto/x509"
	"fmt"
	"time"
)

// CertificateNotAfterValidity returns the duration for which the certificate
// should be valid, based on the template and the earliest expiration date of the CA certificates.
func CertificateNotAfterValidity(template *x509.Certificate, caCerts []*x509.Certificate) (time.Time, error) {
	if len(caCerts) == 0 {
		return time.Time{}, fmt.Errorf("no CA certificates provided")
	}

	// Find the earliest expiration date of the CA certificates
	earliest := caCerts[0].NotAfter
	for _, caCert := range caCerts[1:] {
		if caCert.NotAfter.Before(earliest) {
			earliest = caCert.NotAfter
		}
	}

	// Return the earliest expiration date if it is before the template's NotAfter
	if earliest.Before(template.NotAfter) {
		return earliest, nil
	}

	return template.NotAfter, nil
}
