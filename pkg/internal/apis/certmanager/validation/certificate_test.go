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

package validation

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	internalcmapi "github.com/cert-manager/cert-manager/pkg/internal/apis/certmanager"
	cmmeta "github.com/cert-manager/cert-manager/pkg/internal/apis/meta"
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
		cfg  *internalcmapi.Certificate
		errs []*field.Error
	}{
		"valid basic certificate": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"valid with blank issuerRef kind": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: cmmeta.ObjectReference{
						Name: "valid",
					},
				},
			},
		},
		"valid with 'Issuer' issuerRef kind": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
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
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					Subject: &internalcmapi.X509Subject{
						Organizations: []string{"testorg"},
					},
					IssuerRef: validIssuerRef,
				},
			},
		},
		"invalid issuerRef kind": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
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
		"certificate missing secretName": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("secretName"), "must be specified"),
			},
		},
		"certificate with no domains, URIs or common name": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath, "", "at least one of commonName, dnsNames, uris ipAddresses, or emailAddresses must be set"),
			},
		},
		"certificate with no issuerRef": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
				},
			},
			errs: []*field.Error{
				field.Required(fldPath.Child("issuerRef", "name"), "must be specified"),
			},
		},
		"valid certificate with only dnsNames": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					DNSNames:   []string{"validdnsname"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified and no keySize": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Algorithm: internalcmapi.RSAKeyAlgorithm,
					},
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 2048": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Algorithm: internalcmapi.RSAKeyAlgorithm,
						Size:      2048,
					},
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 4096": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Algorithm: internalcmapi.RSAKeyAlgorithm,
						Size:      4096,
					},
				},
			},
		},
		"valid certificate with rsa keyAlgorithm specified with keySize 8192": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Algorithm: internalcmapi.RSAKeyAlgorithm,
						Size:      8192,
					},
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified and no keySize": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Algorithm: internalcmapi.ECDSAKeyAlgorithm,
					},
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 256": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Size:      256,
						Algorithm: internalcmapi.ECDSAKeyAlgorithm,
					},
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 384": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Size:      384,
						Algorithm: internalcmapi.ECDSAKeyAlgorithm,
					},
				},
			},
		},
		"valid certificate with ecdsa keyAlgorithm specified with keySize 521": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Size:      521,
						Algorithm: internalcmapi.ECDSAKeyAlgorithm,
					},
				},
			},
		},
		"valid certificate with keyAlgorithm not specified and keySize specified": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Size: 2048,
					},
				},
			},
		},
		"certificate with rsa keyAlgorithm specified and invalid keysize 1024": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Algorithm: internalcmapi.RSAKeyAlgorithm,
						Size:      1024,
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("privateKey", "size"), 1024, "must be between 2048 & 8192 for rsa keyAlgorithm"),
			},
		},
		"certificate with rsa keyAlgorithm specified and invalid keysize 8196": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Algorithm: internalcmapi.RSAKeyAlgorithm,
						Size:      8196,
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("privateKey", "size"), 8196, "must be between 2048 & 8192 for rsa keyAlgorithm"),
			},
		},
		"certificate with ecdsa keyAlgorithm specified and invalid keysize": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Size:      100,
						Algorithm: internalcmapi.ECDSAKeyAlgorithm,
					},
				},
			},
			errs: []*field.Error{
				field.NotSupported(fldPath.Child("privateKey", "size"), 100, []string{"256", "384", "521"}),
			},
		},
		"certificate with invalid keyAlgorithm": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Algorithm: internalcmapi.PrivateKeyAlgorithm("blah"),
					},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("privateKey", "algorithm"), internalcmapi.PrivateKeyAlgorithm("blah"), "must be either empty or one of rsa or ecdsa"),
			},
		},
		"valid certificate with ipAddresses": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName:  "testcn",
					IPAddresses: []string{"127.0.0.1"},
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
		},
		"certificate with invalid ipAddresses": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
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
		"valid certificate with commonName exactly 64 bytes": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "this-is-a-big-long-string-which-is-exactly-sixty-four-characters",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{},
		},
		"invalid certificate with commonName longer than 64 bytes": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "this-is-a-big-long-string-which-has-exactly-sixty-five-characters",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.TooLong(fldPath.Child("commonName"), "this-is-a-big-long-string-which-has-exactly-sixty-five-characters", 64),
			},
		},
		"valid certificate with no commonName and second dnsName longer than 64 bytes": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
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
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
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
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					Usages:     []internalcmapi.KeyUsage{"signing"},
				},
			},
		},
		"valid certificate with multiple keyusage": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					Usages:     []internalcmapi.KeyUsage{"signing", "s/mime"},
				},
			},
		},
		"invalid certificate with nonexistent keyusage": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					Usages:     []internalcmapi.KeyUsage{"nonexistent"},
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("usages").Index(0), internalcmapi.KeyUsage("nonexistent"), "unknown keyusage"),
			},
		},
		"valid certificate with only URI SAN name": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					URISANs: []string{
						"foo.bar",
					},
				},
			},
		},
		"valid certificate with only email SAN": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					EmailSANs:  []string{"alice@example.com"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"invalid certificate with incorrect email": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					EmailSANs:  []string{"aliceexample.com"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailAddresses").Index(0), "aliceexample.com", "invalid email address: mail: missing '@' or angle-addr"),
			},
		},
		"invalid certificate with email formatted with name": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					EmailSANs:  []string{"Alice <alice@example.com>"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailAddresses").Index(0), "Alice <alice@example.com>", "invalid email address: make sure the supplied value only contains the email address itself"),
			},
		},
		"invalid certificate with email formatted with mailto": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					EmailSANs:  []string{"mailto:alice@example.com"},
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailAddresses").Index(0), "mailto:alice@example.com", "invalid email address: mail: expected comma"),
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
		cfg  *internalcmapi.Certificate
		errs []*field.Error
	}{
		"default duration and renewBefore": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"valid duration and renewBefore": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					Duration:    usefulDurations["one year"],
					RenewBefore: usefulDurations["half year"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
		},
		"unset duration, valid renewBefore for default": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					RenewBefore: usefulDurations["one month"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
		},
		"unset renewBefore, valid duration for default": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					Duration:   usefulDurations["one year"],
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
		},
		"renewBefore is bigger than the default duration": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					RenewBefore: usefulDurations["ten years"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBefore"), usefulDurations["ten years"].Duration, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", cmapi.DefaultCertificateDuration, usefulDurations["ten years"].Duration))},
		},
		"default renewBefore is bigger than the set duration": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					Duration:   usefulDurations["one hour"],
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBefore"), cmapi.DefaultRenewBefore, fmt.Sprintf("certificate duration %s must be greater than renewBefore %s", usefulDurations["one hour"].Duration, cmapi.DefaultRenewBefore))},
		},
		"renewBefore is bigger than the duration": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
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
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					RenewBefore: usefulDurations["one second"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBefore"), usefulDurations["one second"].Duration, fmt.Sprintf("certificate renewBefore must be greater than %s", cmapi.MinimumRenewBefore))},
		},
		"duration is less than the minimum permitted value": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					Duration:    usefulDurations["half hour"],
					RenewBefore: usefulDurations["ten minutes"],
					CommonName:  "testcn",
					SecretName:  "abc",
					IssuerRef:   validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("duration"), usefulDurations["half hour"].Duration, fmt.Sprintf("certificate duration must be greater than %s", cmapi.MinimumCertificateDuration))},
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
