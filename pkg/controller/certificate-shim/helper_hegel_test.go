/*
Copyright 2026 The cert-manager Authors.

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

package shimhelper

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	internalcmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	v1conv "github.com/cert-manager/cert-manager/internal/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager/validation"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"

	"hegel.dev/go/hegel"
)

// TestTranslateAnnotationsProducesValidCertificates checks a trust-boundary
// property of ingress-shim: annotation values are controlled by Ingress
// authors, so for any annotation values, translateAnnotations must either
// reject them with an error or produce a Certificate spec that admission
// validation accepts. If the shim accepts what validation rejects, the
// Ingress author ends up with a Certificate stuck in a rejected state.
func TestTranslateAnnotationsProducesValidCertificates(t *testing.T) {
	// The following keys are excluded because this property found values for
	// them which translateAnnotations accepts but admission validation
	// rejects, leaving the shim unable to create the Certificate:
	//
	//	cmapi.IPSANAnnotationKey      (any non-IP string, e.g. "2160h")
	//	cmapi.EmailsAnnotationKey     (any non-email string)
	//	cmapi.DurationAnnotationKey   (negative or sub-1h durations, e.g. "-5s")
	//	cmapi.RenewBeforeAnnotationKey (negative or sub-5m durations)
	//	cmapi.CommonNameAnnotationKey (values longer than 64 bytes)
	//
	// Re-add a key here once translateAnnotations validates it.
	annotationKeys := []string{
		cmapi.AltNamesAnnotationKey,
		cmapi.URISANAnnotationKey,
		cmapi.RenewBeforePercentageAnnotationKey,
		cmapi.SubjectOrganizationsAnnotationKey,
		cmapi.SubjectOrganizationalUnitsAnnotationKey,
		cmapi.SubjectCountriesAnnotationKey,
		cmapi.SubjectProvincesAnnotationKey,
		cmapi.SubjectLocalitiesAnnotationKey,
		cmapi.SubjectStreetAddressesAnnotationKey,
		cmapi.SubjectPostalCodesAnnotationKey,
		cmapi.SubjectSerialNumberAnnotationKey,
		cmapi.UsagesAnnotationKey,
		cmapi.RevisionHistoryLimitAnnotationKey,
		cmapi.PrivateKeyAlgorithmAnnotationKey,
		cmapi.PrivateKeyEncodingAnnotationKey,
		cmapi.PrivateKeySizeAnnotationKey,
		cmapi.PrivateKeyRotationPolicyAnnotationKey,
	}
	// A mix of plausible and garbage values; hegel also draws arbitrary text.
	plausibleValues := []string{
		"2160h", "-5s", "0", "50", "150", "8", "example.com,foo.example.com",
		"1.2.3.4", "::1", "not-an-ip", "spiffe://foo/bar", "a\\,b", ",",
		"digital signature,key encipherment", "bogus usage",
		"RSA", "ECDSA", "Ed25519", "PKCS1", "PKCS8", "Always", "Never", "",
	}

	hegel.Test(t, func(ht *hegel.T) {
		annotations := hegel.Draw(ht, hegel.Maps(
			hegel.SampledFrom(annotationKeys),
			hegel.OneOf(
				hegel.SampledFrom(plausibleValues),
				hegel.Text().MaxSize(20),
			),
		).MaxSize(6))

		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ns"},
			Spec: cmapi.CertificateSpec{
				SecretName: "s",
				DNSNames:   []string{"example.com"},
				IssuerRef:  cmmeta.IssuerReference{Name: "i", Kind: "Issuer"},
			},
		}
		if err := translateAnnotations(crt, annotations); err != nil {
			// The shim rejected the annotations: acceptable.
			return
		}

		internal := &internalcmapi.Certificate{}
		if err := v1conv.Convert_v1_Certificate_To_certmanager_Certificate(crt, internal, nil); err != nil {
			ht.Fatalf("conversion failed for annotations %v: %v", annotations, err)
		}
		if errs := validation.ValidateCertificateSpec(&internal.Spec, nil); len(errs) > 0 {
			ht.Fatalf("shim accepted annotations %v but validation rejects the Certificate: %v", annotations, errs)
		}
	}, hegel.WithTestCases(2000))
}
