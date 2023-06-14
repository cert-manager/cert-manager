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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmutil "github.com/cert-manager/cert-manager/pkg/util"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

// AnnotationsForCertificate returns a map which is set on all
// Certificate Secret's Annotations when issued. These annotations contain
// information about the Certificate.
// If the X.509 certificate is nil, an empty map will be returned.
func AnnotationsForCertificate(certificate *x509.Certificate) (map[string]string, error) {
	annotations := make(map[string]string)

	if certificate == nil {
		return annotations, nil
	}

	// TODO: the reason that for some annotations we keep empty annotations and we don't for others is not clear.
	// The keepEmpty parameter is only used here to maintain this unexplained previous behaviour.

	var encodingErr error
	addStringAnnotation := func(keepEmpty bool, key string, value string) {
		if len(value) == 0 && !keepEmpty {
			return
		}
		annotations[key] = value
	}
	addCSVEncodedAnnotation := func(keepEmpty bool, key string, values []string) {
		if len(values) == 0 && !keepEmpty {
			return
		}

		csvString, err := cmutil.JoinWithEscapeCSV(values)
		if err != nil {
			encodingErr = err
			return
		}
		annotations[key] = csvString
	}

	addStringAnnotation(true, cmapi.CommonNameAnnotationKey, certificate.Subject.CommonName)
	addStringAnnotation(false, cmapi.SubjectSerialNumberAnnotationKey, certificate.Subject.SerialNumber)

	addCSVEncodedAnnotation(false, cmapi.SubjectOrganizationsAnnotationKey, certificate.Subject.Organization)
	addCSVEncodedAnnotation(false, cmapi.SubjectOrganizationalUnitsAnnotationKey, certificate.Subject.OrganizationalUnit)
	addCSVEncodedAnnotation(false, cmapi.SubjectCountriesAnnotationKey, certificate.Subject.Country)
	addCSVEncodedAnnotation(false, cmapi.SubjectProvincesAnnotationKey, certificate.Subject.Province)
	addCSVEncodedAnnotation(false, cmapi.SubjectLocalitiesAnnotationKey, certificate.Subject.Locality)
	addCSVEncodedAnnotation(false, cmapi.SubjectPostalCodesAnnotationKey, certificate.Subject.PostalCode)
	addCSVEncodedAnnotation(false, cmapi.SubjectStreetAddressesAnnotationKey, certificate.Subject.StreetAddress)

	addCSVEncodedAnnotation(false, cmapi.EmailsAnnotationKey, certificate.EmailAddresses)
	addCSVEncodedAnnotation(true, cmapi.AltNamesAnnotationKey, certificate.DNSNames)
	addCSVEncodedAnnotation(true, cmapi.IPSANAnnotationKey, utilpki.IPAddressesToString(certificate.IPAddresses))
	addCSVEncodedAnnotation(true, cmapi.URISANAnnotationKey, utilpki.URLsToString(certificate.URIs))

	if encodingErr != nil {
		return nil, encodingErr
	}

	return annotations, nil
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
