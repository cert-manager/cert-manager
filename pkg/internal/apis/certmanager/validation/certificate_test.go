/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package validation

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmapi "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	cmmeta "github.com/jetstack/cert-manager/pkg/internal/apis/meta"
)

var (
	validIssuerRef = cmmeta.ObjectReference{
		Name: "name",
		Kind: "ClusterIssuer",
	}
)

func strPtr(s string) *string {
	return &s
}

func TestValidateCertificate(t *testing.T) {
	fldPath := field.NewPath("spec")
	scenarios := map[string]struct {
		cfg  *cmapi.Certificate
		errs []*field.Error
	}{
		"valid basic certificate": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"valid with blank issuerRef kind": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: cmmeta.ObjectReference{
						Name: "valid",
					},
				},
			},
		},
		"valid with 'Issuer' issuerRef kind": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: cmmeta.ObjectReference{
						Name: "valid",
						Kind: "Issuer",
					},
				},
			},
		},
		"valid with org set": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					Subject: &cmapi.X509Subject{
						Organizations: []string{"testorg"},
					},
					IssuerRef: validIssuerRef,
				},
			},
		},
		"invalid issuerRef kind": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: cmmeta.ObjectReference{
						Name: "valid",
						Kind: "invalid",
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("issuerRef", "kind"), "invalid", "must be one of Issuer or ClusterIssuer"),
			},
		},
		"certificate with no domains, URIs or common name": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath, "", "at least one of commonName, dnsNames, uriSANs or emailSANs must be set"),
			},
		},
		"valid certificate with only dnsNames": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					DNSNames:   []string{"validdnsname"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified and no keySize": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.RSAKeyAlgorithm,
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 2048": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.RSAKeyAlgorithm,
					KeySize:      2048,
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 4096": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.RSAKeyAlgorithm,
					KeySize:      4096,
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 8192": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.RSAKeyAlgorithm,
					KeySize:      8192,
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified and no keySize": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.ECDSAKeyAlgorithm,
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 256": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.ECDSAKeyAlgorithm,
					KeySize:      256,
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 384": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.ECDSAKeyAlgorithm,
					KeySize:      384,
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 521": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.ECDSAKeyAlgorithm,
					KeySize:      521,
				},
			},
		},
		"valid certificate with keyAlgorithm not specified and keySize specified": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					KeySize:    2048,
				},
			},
		},
		"certificate with rsa keyAlgorithm specified and invalid keysize 1024": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.RSAKeyAlgorithm,
					KeySize:      1024,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keySize"), 1024, "must be between 2048 & 8192 for rsa keyAlgorithm"),
			},
		},
		"certificate with rsa keyAlgorithm specified and invalid keysize 8196": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.RSAKeyAlgorithm,
					KeySize:      8196,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keySize"), 8196, "must be between 2048 & 8192 for rsa keyAlgorithm"),
			},
		},
		"certificate with ecdsa keyAlgorithm specified and invalid keysize": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.ECDSAKeyAlgorithm,
					KeySize:      100,
				},
			},
			errs: []*field.Error{
				field.NotSupported(fldPath.Child("keySize"), 100, []string{"256", "384", "521"}),
			},
		},
		"certificate with invalid keyAlgorithm": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:   "testcn",
					SecretName:   "abc",
					IssuerRef:    validIssuerRef,
					KeyAlgorithm: cmapi.KeyAlgorithm("blah"),
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("keyAlgorithm"), cmapi.KeyAlgorithm("blah"), "must be either empty or one of rsa or ecdsa"),
			},
		},
		"valid certificate with ipAddresses": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:  "testcn",
					IPAddresses: []string{"127.0.0.1"},
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
		},
		"certificate with invalid ipAddresses": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName:  "testcn",
					IPAddresses: []string{"blah"},
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("ipAddresses").Index(0), "blah", "invalid IP address"),
			},
		},
		"valid certificate with no commonName and second dnsName longer than 64 bytes": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					DNSNames: []string{
						"dnsName",
						"this-is-a-big-long-string-which-has-exactly-sixty-five-characters",
					},
				},
			},
		},
		"valid certificate with commonName and first dnsName longer than 64 bytes": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					DNSNames: []string{
						"this-is-a-big-long-string-which-has-exactly-sixty-five-characters",
						"dnsName",
					},
				},
			},
		},
		"valid certificate with basic keyusage": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					Usages:     []cmapi.KeyUsage{"signing"},
				},
			},
		},
		"valid certificate with multiple keyusage": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					Usages:     []cmapi.KeyUsage{"signing", "s/mime"},
				},
			},
		},
		"invalid certificate with nonexistant keyusage": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					Usages:     []cmapi.KeyUsage{"nonexistant"},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("usages").Index(0), cmapi.KeyUsage("nonexistant"), "unknown keyusage"),
			},
		},
		"valid certificate with only URI SAN name": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					URISANs: []string{
						"foo.bar",
					},
				},
			},
		},
		"valid certificate with only email SAN": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					EmailSANs:  []string{"alice@example.com"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"invalid certificate with incorrect email": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					EmailSANs:  []string{"aliceexample.com"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailSANs").Index(0), "aliceexample.com", "invalid email address: mail: missing '@' or angle-addr"),
			},
		},
		"invalid certificate with email formatted with name": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					EmailSANs:  []string{"Alice <alice@example.com>"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailSANs").Index(0), "Alice <alice@example.com>", "invalid email address: make sure the supplied value only contains the email address itself"),
			},
		},
		"invalid certificate with email formatted with mailto": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					EmailSANs:  []string{"mailto:alice@example.com"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailSANs").Index(0), "mailto:alice@example.com", "invalid email address: mail: expected comma"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateCertificate(s.cfg)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}

func TestValidateDuration(t *testing.T) {
	usefulDurations := map[string]*metav1.Duration{
		"one second":  {Duration: time.Second},
		"ten minutes": {Duration: time.Minute * 10},
		"half hour":   {Duration: time.Minute * 30},
		"one hour":    {Duration: time.Hour},
		"one month":   {Duration: time.Hour * 24 * 30},
		"half year":   {Duration: time.Hour * 24 * 180},
		"one year":    {Duration: time.Hour * 24 * 365},
		"ten years":   {Duration: time.Hour * 24 * 365 * 10},
	}

	fldPath := field.NewPath("spec")
	scenarios := map[string]struct {
		cfg  *cmapi.Certificate
		errs []*field.Error
	}{
		"default duration and renewBefore": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"valid duration and renewBefore": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Duration:    usefulDurations["one year"],
					RenewBefore: usefulDurations["half year"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
		},
		"unset duration, valid renewBefore for default": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					RenewBefore: usefulDurations["one month"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
		},
		"unset renewBefore, valid duration for default": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Duration:   usefulDurations["one year"],
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"renewBefore is bigger than the default duration": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					RenewBefore: usefulDurations["ten years"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBefore"), usefulDurations["ten years"].Duration, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", cmapiv1alpha2.DefaultCertificateDuration, usefulDurations["ten years"].Duration))},
		},
		"default renewBefore is bigger than the set duration": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Duration:   usefulDurations["one hour"],
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBefore"), cmapiv1alpha2.DefaultRenewBefore, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", usefulDurations["one hour"].Duration, cmapiv1alpha2.DefaultRenewBefore))},
		},
		"renewBefore is bigger than the duration": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Duration:    usefulDurations["one month"],
					RenewBefore: usefulDurations["one year"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBefore"), usefulDurations["one year"].Duration, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", usefulDurations["one month"].Duration, usefulDurations["one year"].Duration))},
		},
		"renewBefore is less than the minimum permitted value": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					RenewBefore: usefulDurations["one second"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBefore"), usefulDurations["one second"].Duration, fmt.Sprintf("certificate renewBefore must be greater than %s", cmapiv1alpha2.MinimumRenewBefore))},
		},
		"duration is less than the minimum permitted value": {
			cfg: &cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					Duration:    usefulDurations["half hour"],
					RenewBefore: usefulDurations["ten minutes"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("duration"), usefulDurations["half hour"].Duration, fmt.Sprintf("certificate duration must be greater than %s", cmapiv1alpha2.MinimumCertificateDuration))},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			errs := ValidateDuration(&s.cfg.Spec, fldPath)
			if len(errs) != len(s.errs) {
				t.Errorf("Expected %v but got %v", s.errs, errs)
				return
			}
			for i, e := range errs {
				expectedErr := s.errs[i]
				if !reflect.DeepEqual(e, expectedErr) {
					t.Errorf("Expected %v but got %v", expectedErr, e)
				}
			}
		})
	}
}
