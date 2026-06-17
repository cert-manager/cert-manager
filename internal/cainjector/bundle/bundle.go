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

package bundle

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"k8s.io/utils/set"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// AppendCertificatesToBundle will append the provided certificates to the
// provided bundle, if the certificate already exists in the bundle then it is
// not re-added.
//
// Additionally expired certificates are removed from the bundle.
func AppendCertificatesToBundle(bundle []byte, additional []byte) ([]byte, error) {
	certificatesFromBundle, err := pki.DecodeX509CertificateSetBytes(bundle)
	if err != nil && len(bundle) != 0 {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}

	certificatesToMerge, err := pki.DecodeX509CertificateSetBytes(additional)
	if err != nil && len(additional) != 0 {
		return nil, fmt.Errorf("failed to parse additional certificates: %w", err)
	}

	certificatesSeen := set.New[string]()
	certificatesMerged := make([]*x509.Certificate, 0, len(certificatesFromBundle)+len(certificatesToMerge))

	// We delete expired certificates from the bundle, for this we will
	// repeatedly need the current time
	now := time.Now()

	// Merge in all certificates that already exist in the bundle
	for _, certificate := range certificatesFromBundle {
		raw := string(certificate.Raw)
		if !certificatesSeen.Has(raw) && !now.After(certificate.NotAfter) {
			certificatesMerged = append(certificatesMerged, certificate)
			certificatesSeen.Insert(raw)
		}
	}

	// Merge in all additional certificates
	for _, certificate := range certificatesToMerge {
		raw := string(certificate.Raw)
		if !certificatesSeen.Has(raw) && !now.After(certificate.NotAfter) {
			certificatesMerged = append(certificatesMerged, certificate)
			certificatesSeen.Insert(raw)
		}
	}

	// Build the chain
	buff := bytes.NewBuffer([]byte{})
	for _, certificate := range certificatesMerged {
		if err := pem.Encode(buff, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			return nil, fmt.Errorf("failed encode certificate in PEM format: %w", err)
		}
	}

	return buff.Bytes(), nil
}
