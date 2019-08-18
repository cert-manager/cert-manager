package fuzzer

import (
	fuzz "github.com/google/gofuzz"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
)

// Funcs returns the fuzzer functions for the apps api group.
var Funcs = func(codecs runtimeserializer.CodecFactory) []interface{} {
	return []interface{}{
		func(s *certmanager.Certificate, c fuzz.Continue) {
			c.FuzzNoCustom(s) // fuzz self without calling this function again

			if len(s.Spec.DNSNames) == 0 {
				s.Spec.DNSNames = []string{s.Spec.CommonName}
			}
			if s.Spec.IssuerRef.Kind == "" {
				s.Spec.IssuerRef.Kind = v1alpha1.IssuerKind
			}
			if s.Spec.Duration == nil {
				s.Spec.Duration = &metav1.Duration{Duration: v1alpha1.DefaultCertificateDuration}
			}
			if s.Spec.RenewBefore == nil {
				s.Spec.RenewBefore = &metav1.Duration{Duration: v1alpha1.DefaultRenewBefore}
			}
		},
		func(s *certmanager.Order, c fuzz.Continue) {
			c.FuzzNoCustom(s) // fuzz self without calling this function again

			if s.Spec.IssuerRef.Kind == "" {
				s.Spec.IssuerRef.Kind = v1alpha1.IssuerKind
			}
		},
		func(s *certmanager.Challenge, c fuzz.Continue) {
			c.FuzzNoCustom(s) // fuzz self without calling this function again

			if s.Spec.IssuerRef.Kind == "" {
				s.Spec.IssuerRef.Kind = v1alpha1.IssuerKind
			}
		},
		func(s *certmanager.CertificateRequest, c fuzz.Continue) {
			c.FuzzNoCustom(s) // fuzz self without calling this function again

			if s.Spec.IssuerRef.Kind == "" {
				s.Spec.IssuerRef.Kind = v1alpha1.IssuerKind
			}
			if s.Spec.Duration == nil {
				s.Spec.Duration = &metav1.Duration{Duration: v1alpha1.DefaultCertificateDuration}
			}
		},
		func(s *certmanager.ACMEIssuerDNS01ProviderWebhook, c fuzz.Continue) {
			c.FuzzNoCustom(s) // fuzz self without calling this function again
			// ensure the webhook's config is valid JSON
			s.Config = &apiext.JSON{Raw:[]byte("{}")}
		},
	}
}
