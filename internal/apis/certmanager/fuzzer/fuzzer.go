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

package fuzzer

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/randfill"

	acmefuzzer "github.com/cert-manager/cert-manager/internal/apis/acme/fuzzer"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// Funcs returns the fuzzer functions for the apps api group.
var Funcs = func(codecs runtimeserializer.CodecFactory) []interface{} {
	return append(acmefuzzer.Funcs(codecs), []interface{}{
		func(s *certmanager.Certificate, c randfill.Continue) {
			c.FillNoCustom(s) // fuzz self without calling this function again

			if len(s.Spec.DNSNames) == 0 {
				s.Spec.DNSNames = []string{s.Spec.CommonName}
			}
			if s.Spec.IssuerRef.Group == "" {
				s.Spec.IssuerRef.Group = "cert-manager.io"
			}
			if s.Spec.IssuerRef.Kind == "" {
				s.Spec.IssuerRef.Kind = v1.IssuerKind
			}
			if s.Spec.Duration == nil {
				s.Spec.Duration = &metav1.Duration{Duration: v1.DefaultCertificateDuration}
			}
		},
		func(s *certmanager.CertificateRequest, c randfill.Continue) {
			c.FillNoCustom(s) // fuzz self without calling this function again

			if s.Spec.IssuerRef.Group == "" {
				s.Spec.IssuerRef.Group = "cert-manager.io"
			}
			if s.Spec.IssuerRef.Kind == "" {
				s.Spec.IssuerRef.Kind = v1.IssuerKind
			}
			if s.Spec.Duration == nil {
				s.Spec.Duration = &metav1.Duration{Duration: v1.DefaultCertificateDuration}
			}
		},
		func(s *certmanager.VaultAuth, c randfill.Continue) {
			// VaultAuth is a union type - only one auth method should be set.
			// Pick one auth method randomly and only fuzz that one.
			switch c.Int() % 7 {
			case 0:
				c.Fill(&s.TokenSecretRef)
			case 1:
				c.Fill(&s.AppRole)
			case 2:
				c.Fill(&s.ClientCertificate)
			case 3:
				c.Fill(&s.Kubernetes)
			case 4:
				c.Fill(&s.AWS)
			case 5:
				c.Fill(&s.GCP)
			case 6:
				c.Fill(&s.Azure)
			}
		},
	}...)
}
