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

package certificates

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

// AnnotationsForCertificateSecret returns a map which is set on all
// Certificate Secret's Annotations when issued. These annotations contain
// information about the Issuer and Certificate.
// If the X.509 certificate is not-nil, additional annotations will be added
// relating to its Common Name and Subject Alternative Names.
func AnnotationsForCertificateSecret(crt *cmapi.Certificate, certificate *x509.Certificate) map[string]string {
	annotations := make(map[string]string)

	annotations[cmapi.CertificateNameKey] = crt.Name
	annotations[cmapi.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	annotations[cmapi.IssuerKindAnnotationKey] = apiutil.IssuerKind(crt.Spec.IssuerRef)
	annotations[cmapi.IssuerGroupAnnotationKey] = crt.Spec.IssuerRef.Group

	// Only add certificate data if certificate is non-nil.
	if certificate != nil {
		annotations[cmapi.CommonNameAnnotationKey] = certificate.Subject.CommonName
		annotations[cmapi.AltNamesAnnotationKey] = strings.Join(certificate.DNSNames, ",")
		annotations[cmapi.IPSANAnnotationKey] = strings.Join(utilpki.IPAddressesToString(certificate.IPAddresses), ",")
		annotations[cmapi.URISANAnnotationKey] = strings.Join(utilpki.URLsToString(certificate.URIs), ",")
	}

	return annotations
}

// OutputFormatDER returns the byte slice of the private key in DER format. To
// be used for Certificate's Additional Output Format DER.
func OutputFormatDER(privateKey []byte) []byte {
	block, _ := pem.Decode(privateKey)
	return block.Bytes
}

// OutputFormatCombinedPEM returns the byte slice of the PEM encoded private
// key and signed certificate chain, concatenated. To be used for Certificate's
// Additional Output Format Combined PEM.
func OutputFormatCombinedPEM(privateKey, certificate []byte) []byte {
	return bytes.Join([][]byte{privateKey, certificate}, []byte("\n"))
}
