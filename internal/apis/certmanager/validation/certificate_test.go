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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/utils/ptr"

	internalcmapi "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
	"github.com/cert-manager/cert-manager/internal/webhook/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

var (
	validIssuerRef = cmmeta.ObjectReference{
		Name: "name",
		Kind: "ClusterIssuer",
	}
	someAdmissionRequest = &admissionv1.AdmissionRequest{
		RequestKind: &metav1.GroupVersionKind{
			Group:   "test",
			Kind:    "test",
			Version: "test",
		},
	}
	maxSecretTemplateAnnotationsBytesLimit = 256 * (1 << 10) // 256 kB
)

func TestValidateCertificate(t *testing.T) {
	fldPath := field.NewPath("spec")
	scenarios := map[string]struct {
		cfg                           *internalcmapi.Certificate
		a                             *admissionv1.AdmissionRequest
		errs                          []*field.Error
		warnings                      []string
		nameConstraintsFeatureEnabled bool
	}{
		"valid basic certificate": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			a: someAdmissionRequest,
		},
		"valid with blank issuerRef kind and no group": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: cmmeta.ObjectReference{
						Name: "valid",
					},
				},
			},
			a: someAdmissionRequest,
		},
		"valid with 'Issuer' issuerRef kind and no group": {
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
		},
		"valid with 'Issuer' issuerRef kind and explicit internal group": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "valid",
						Kind:  "Issuer",
						Group: "cert-manager.io",
					},
				},
			},
			a: someAdmissionRequest,
		},
		"invalid with external issuerRef kind and empty group": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: cmmeta.ObjectReference{
						Name: "abc",
						Kind: "AWSPCAClusterIssuer",
					},
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("issuerRef", "kind"), "AWSPCAClusterIssuer", "must be one of Issuer or ClusterIssuer (did you forget to set spec.issuerRef.kind.group?)"),
			},
		},
		"valid with external issuerRef kind and external group": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "abc",
						Kind:  "AWSPCAClusterIssuer",
						Group: "awspca.cert-manager.io",
					},
				},
			},
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
		},
		"certificate invalid secretName": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					IssuerRef:  validIssuerRef,
					SecretName: "testFoo",
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("secretName"), "testFoo", "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')"),
			},
			a: someAdmissionRequest,
		},
		"certificate with no domains, URIs or common name": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath, "", "at least one of commonName (from the commonName field or from a literalSubject), dnsNames, uriSANs, ipAddresses, emailSANs or otherNames must be set"),
			},
		},
		"invalid with no issuerRef": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
				},
			},
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
		},
		"valid certificate with ed25519 keyAlgorithm": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					PrivateKey: &internalcmapi.CertificatePrivateKey{
						Size:      521,
						Algorithm: internalcmapi.Ed25519KeyAlgorithm,
					},
				},
			},
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("privateKey", "algorithm"), internalcmapi.PrivateKeyAlgorithm("blah"), "must be either empty or one of rsa, ecdsa or ed25519"),
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a:    someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
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
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("usages").Index(0), internalcmapi.KeyUsage("nonexistent"), "unknown keyusage"),
			},
		},
		"valid certificate with only URI SAN name": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					SecretName: "abc",
					IssuerRef:  validIssuerRef,
					URIs: []string{
						"foo.bar",
					},
				},
			},
			a: someAdmissionRequest,
		},
		"valid certificate with only email SAN": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					EmailAddresses: []string{"alice@example.com"},
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
		},
		"invalid certificate with incorrect email": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					EmailAddresses: []string{"aliceexample.com"},
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailAddresses").Index(0), "aliceexample.com", "invalid email address: mail: missing '@' or angle-addr"),
			},
		},
		"invalid certificate with email formatted with name": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					EmailAddresses: []string{"Alice <alice@example.com>"},
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailAddresses").Index(0), "Alice <alice@example.com>", "invalid email address: make sure the supplied value only contains the email address itself"),
			},
		},
		"invalid certificate with email formatted with mailto": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					EmailAddresses: []string{"mailto:alice@example.com"},
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("emailAddresses").Index(0), "mailto:alice@example.com", "invalid email address: mail: expected comma"),
			},
		},
		"valid certificate with revision history limit == 1": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName:           "abc",
					SecretName:           "abc",
					IssuerRef:            validIssuerRef,
					RevisionHistoryLimit: ptr.To(int32(1)),
				},
			},
			a: someAdmissionRequest,
		},
		"invalid certificate with revision history limit < 1": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName:           "abc",
					SecretName:           "abc",
					IssuerRef:            validIssuerRef,
					RevisionHistoryLimit: ptr.To(int32(0)),
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("revisionHistoryLimit"), int32(0), "must not be less than 1"),
			},
		},
		"valid with empty secretTemplate": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					SecretTemplate: &internalcmapi.CertificateSecretTemplate{
						Annotations: map[string]string{},
						Labels:      map[string]string{},
					},
					IssuerRef: validIssuerRef,
				},
			},
			a: someAdmissionRequest,
		},
		"valid with 'CertificateSecretTemplate' labels and annotations": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					SecretTemplate: &internalcmapi.CertificateSecretTemplate{
						Annotations: map[string]string{
							"my-annotation.com/foo": "app=bar",
						},
						Labels: map[string]string{
							"my-label.com/foo": "evn-production",
						},
					},
					IssuerRef: validIssuerRef,
				},
			},
			a: someAdmissionRequest,
		},
		"invalid with disallowed 'CertificateSecretTemplate' annotations": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					SecretTemplate: &internalcmapi.CertificateSecretTemplate{
						Annotations: map[string]string{
							"app.com/valid":                          "valid",
							"cert-manager.io/alt-names":              "example.com",
							"cert-manager.io/certificate-name":       "selfsigned-cert",
							"cert-manager.io/allow-direct-injection": "true",
						},
					},
					IssuerRef: validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath.Child("secretTemplate", "annotations"), "cert-manager.io/alt-names", "cert-manager.io/* annotations are not allowed"),
				field.Invalid(fldPath.Child("secretTemplate", "annotations"), "cert-manager.io/certificate-name", "cert-manager.io/* annotations are not allowed"),
			},
		},
		"invalid due to too long 'CertificateSecretTemplate' annotations": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					SecretTemplate: &internalcmapi.CertificateSecretTemplate{
						Annotations: map[string]string{
							"app.com/invalid": strings.Repeat("0", maxSecretTemplateAnnotationsBytesLimit),
						},
					},
					IssuerRef: validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.TooLong(fldPath.Child("secretTemplate", "annotations"), "", maxSecretTemplateAnnotationsBytesLimit),
			},
		},
		"invalid due to not allowed 'CertificateSecretTemplate' labels": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					SecretTemplate: &internalcmapi.CertificateSecretTemplate{
						Labels: map[string]string{
							"app.com/invalid-chars": "invalid=chars",
						},
					},
					IssuerRef: validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(
					fldPath.Child("secretTemplate", "labels"),
					"invalid=chars", "a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an "+
						"alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')"),
			},
		},
		"valid with name constraints": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IsCA:       true,
					NameConstraints: &internalcmapi.NameConstraints{
						Permitted: &internalcmapi.NameConstraintItem{
							DNSDomains: []string{"example.com"},
						},
					},
					IssuerRef: validIssuerRef,
				},
			},
			a:                             someAdmissionRequest,
			nameConstraintsFeatureEnabled: true,
		},
		"invalid with name constraints": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName:      "testcn",
					SecretName:      "abc",
					IsCA:            true,
					NameConstraints: &internalcmapi.NameConstraints{},
					IssuerRef:       validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(
					fldPath.Child("nameConstraints"), &internalcmapi.NameConstraints{}, "either permitted or excluded must be set"),
			},
			nameConstraintsFeatureEnabled: true,
		},
		"valid name constraints with feature gate disabled": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName: "testcn",
					SecretName: "abc",
					IsCA:       true,
					NameConstraints: &internalcmapi.NameConstraints{
						Permitted: &internalcmapi.NameConstraintItem{
							DNSDomains: []string{"example.com"},
						},
					},
					IssuerRef: validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Forbidden(
					fldPath.Child("nameConstraints"), "feature gate NameConstraints must be enabled"),
			},
		},
	}
	for n, s := range scenarios {
		t.Run(n, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.NameConstraints, s.nameConstraintsFeatureEnabled)
			errs, warnings := ValidateCertificate(s.a, s.cfg)
			assert.ElementsMatch(t, errs, s.errs)
			assert.ElementsMatch(t, warnings, s.warnings)
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
		"renewBefore and renewBeforePercentage both set": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					RenewBefore:           usefulDurations["one month"],
					RenewBeforePercentage: ptr.To(int32(95)),
					CommonName:            "testcn",
					SecretName:            "abc",
					IssuerRef:             validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(fldPath.Child("renewBefore"), usefulDurations["one month"].Duration, "renewBefore and renewBeforePercentage are mutually exclusive and cannot both be set"),
				field.Invalid(fldPath.Child("renewBeforePercentage"), int32(95), "renewBefore and renewBeforePercentage are mutually exclusive and cannot both be set"),
			},
		},
		"valid duration and renewBeforePercentage": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					Duration:              usefulDurations["one year"],
					RenewBeforePercentage: ptr.To(int32(95)),
					CommonName:            "testcn",
					SecretName:            "abc",
					IssuerRef:             validIssuerRef,
				},
			},
		},
		"unset duration, valid renewBeforePercentage for default": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					RenewBeforePercentage: ptr.To(int32(95)),
					CommonName:            "testcn",
					SecretName:            "abc",
					IssuerRef:             validIssuerRef,
				},
			},
		},
		"renewBeforePercentage is equal to duration": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					RenewBeforePercentage: ptr.To(int32(0)),
					CommonName:            "testcn",
					SecretName:            "abc",
					IssuerRef:             validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBeforePercentage"), int32(0), "certificate renewBeforePercentage must result in a renewBefore less than duration")},
		},
		"renewBeforePercentage results in less than the minimum permitted value": {
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					RenewBeforePercentage: ptr.To(int32(100)),
					CommonName:            "testcn",
					SecretName:            "abc",
					IssuerRef:             validIssuerRef,
				},
			},
			errs: []*field.Error{field.Invalid(fldPath.Child("renewBeforePercentage"), int32(100), fmt.Sprintf("certificate renewBeforePercentage must result in a renewBefore greater than %s", cmapi.MinimumRenewBefore))},
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
			assert.ElementsMatch(t, errs, s.errs)
		})
	}
}

func Test_validateAdditionalOutputFormats(t *testing.T) {
	tests := map[string]struct {
		featureEnabled bool
		spec           *internalcmapi.CertificateSpec
		expErr         field.ErrorList
	}{
		"if feature disabled and no formats defined, expect no error": {
			featureEnabled: false,
			spec: &internalcmapi.CertificateSpec{
				AdditionalOutputFormats: []internalcmapi.CertificateAdditionalOutputFormat{},
			},
			expErr: nil,
		},
		"if feature disabled and 1 format defined, expect error": {
			featureEnabled: false,
			spec: &internalcmapi.CertificateSpec{
				AdditionalOutputFormats: []internalcmapi.CertificateAdditionalOutputFormat{
					{Type: internalcmapi.CertificateOutputFormatType("foo")},
				},
			},
			expErr: field.ErrorList{
				field.Forbidden(field.NewPath("spec", "additionalOutputFormats"), "feature gate AdditionalCertificateOutputFormats must be enabled"),
			},
		},
		"if feature disabled and multiple formats defined, expect error": {
			featureEnabled: false,
			spec: &internalcmapi.CertificateSpec{
				AdditionalOutputFormats: []internalcmapi.CertificateAdditionalOutputFormat{
					{Type: internalcmapi.CertificateOutputFormatType("foo")},
					{Type: internalcmapi.CertificateOutputFormatType("bar")},
					{Type: internalcmapi.CertificateOutputFormatType("random")},
				},
			},
			expErr: field.ErrorList{
				field.Forbidden(field.NewPath("spec", "additionalOutputFormats"), "feature gate AdditionalCertificateOutputFormats must be enabled"),
			},
		},
		"if feature enabled and no formats defined, expect no error": {
			featureEnabled: true,
			spec: &internalcmapi.CertificateSpec{
				AdditionalOutputFormats: []internalcmapi.CertificateAdditionalOutputFormat{},
			},
			expErr: nil,
		},
		"if feature enabled and single format defined, expect no error": {
			featureEnabled: true,
			spec: &internalcmapi.CertificateSpec{
				AdditionalOutputFormats: []internalcmapi.CertificateAdditionalOutputFormat{
					{Type: internalcmapi.CertificateOutputFormatType("foo")},
				},
			},
			expErr: nil,
		},
		"if feature enabled and multiple unique formats defined, expect no error": {
			featureEnabled: true,
			spec: &internalcmapi.CertificateSpec{
				AdditionalOutputFormats: []internalcmapi.CertificateAdditionalOutputFormat{
					{Type: internalcmapi.CertificateOutputFormatType("foo")},
					{Type: internalcmapi.CertificateOutputFormatType("bar")},
					{Type: internalcmapi.CertificateOutputFormatType("random")},
				},
			},
			expErr: nil,
		},
		"if feature enabled and multiple formats defined but 2 non-unique, expect error": {
			featureEnabled: true,
			spec: &internalcmapi.CertificateSpec{
				AdditionalOutputFormats: []internalcmapi.CertificateAdditionalOutputFormat{
					{Type: internalcmapi.CertificateOutputFormatType("foo")},
					{Type: internalcmapi.CertificateOutputFormatType("bar")},
					{Type: internalcmapi.CertificateOutputFormatType("random")},
					{Type: internalcmapi.CertificateOutputFormatType("foo")},
				},
			},
			expErr: field.ErrorList{
				field.Duplicate(field.NewPath("spec", "additionalOutputFormats").Key("type"), "foo"),
			},
		},
		"if feature enabled and multiple formats defined but multiple non-unique, expect error": {
			featureEnabled: true,
			spec: &internalcmapi.CertificateSpec{
				AdditionalOutputFormats: []internalcmapi.CertificateAdditionalOutputFormat{
					{Type: internalcmapi.CertificateOutputFormatType("foo")},
					{Type: internalcmapi.CertificateOutputFormatType("bar")},
					{Type: internalcmapi.CertificateOutputFormatType("random")},
					{Type: internalcmapi.CertificateOutputFormatType("random")},
					{Type: internalcmapi.CertificateOutputFormatType("foo")},
					{Type: internalcmapi.CertificateOutputFormatType("bar")},
					{Type: internalcmapi.CertificateOutputFormatType("bar")},
					{Type: internalcmapi.CertificateOutputFormatType("123")},
					{Type: internalcmapi.CertificateOutputFormatType("456")},
				},
			},
			expErr: field.ErrorList{
				field.Duplicate(field.NewPath("spec", "additionalOutputFormats").Key("type"), "random"),
				field.Duplicate(field.NewPath("spec", "additionalOutputFormats").Key("type"), "foo"),
				field.Duplicate(field.NewPath("spec", "additionalOutputFormats").Key("type"), "bar"),
				field.Duplicate(field.NewPath("spec", "additionalOutputFormats").Key("type"), "bar"),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.AdditionalCertificateOutputFormats, test.featureEnabled)
			gotErr := validateAdditionalOutputFormats(test.spec, field.NewPath("spec"))
			assert.Equal(t, test.expErr, gotErr)
		})
	}
}

func Test_validateLiteralSubject(t *testing.T) {
	fldPath := field.NewPath("spec")
	tests := map[string]struct {
		featureEnabled bool
		cfg            *internalcmapi.Certificate
		a              *admissionv1.AdmissionRequest
		errs           []*field.Error
	}{
		"featureGate should be enabled to use literalSubject": {
			featureEnabled: false,
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					LiteralSubject: "CN=testcn",
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Forbidden(fldPath.Child("literalSubject"), "Feature gate LiteralCertificateSubject must be enabled on both webhook and controller to use the alpha `literalSubject` field"),
			},
			a: someAdmissionRequest,
		},
		"valid with only `literalSubject` and no `Subject`  or `CommonName` provided": {
			featureEnabled: true,
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					LiteralSubject: "CN=testcn",
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
		},
		"valid with only `literalSubject` and only a `Subject.SerialNumber` provided": {
			featureEnabled: true,
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					Subject:        &internalcmapi.X509Subject{SerialNumber: "1"},
					LiteralSubject: "CN=testcn",
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			errs: []*field.Error{
				field.Invalid(
					fldPath.Child("subject"),
					&internalcmapi.X509Subject{SerialNumber: "1"}, "When providing a `LiteralSubject` no `Subject` properties may be provided."),
			},
			a: someAdmissionRequest,
		},
		"valid with a `literalSubject` containing CN with special characters, multiple DC and well-known rfc4514 and rfc5280 RDN OIDs": {
			featureEnabled: true,
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					LiteralSubject: "CN=James \\\"Jim\\\" Smith\\, III,DC=dc,DC=net,UID=jamessmith,STREET=La Rambla,L=Barcelona,C=Spain,O=Acme,OU=IT,OU=Admins",
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
		},
		"invalid with a `literalSubject` without CN and no dnsNames, ipAddresses, or emailAddress": {
			featureEnabled: true,
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					LiteralSubject: "O=SomeCorp",
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(fldPath, "", "at least one of commonName (from the commonName field or from a literalSubject), dnsNames, uriSANs, ipAddresses, emailSANs or otherNames must be set"),
			},
		},
		"invalid with a `literalSubject` and any `Subject` other than serialNumber": {
			featureEnabled: true,
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					Subject:        &internalcmapi.X509Subject{Organizations: []string{"US"}},
					LiteralSubject: "CN=testcn",
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(
					fldPath.Child("subject"),
					&internalcmapi.X509Subject{Organizations: []string{"US"}}, "When providing a `LiteralSubject` no `Subject` properties may be provided."),
			},
		},
		"invalid with a `literalSubject` and a `commonName`": {
			featureEnabled: true,
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					CommonName:     "testcn",
					LiteralSubject: "CN=testcn",
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(
					fldPath.Child("commonName"),
					"testcn", "When providing a `LiteralSubject` no `commonName` may be provided."),
			},
		},
		"invalid with an unknown OID": {
			featureEnabled: true,
			cfg: &internalcmapi.Certificate{
				Spec: internalcmapi.CertificateSpec{
					LiteralSubject: "C=O,B=TX,CN=foo",
					SecretName:     "abc",
					IssuerRef:      validIssuerRef,
				},
			},
			a: someAdmissionRequest,
			errs: []*field.Error{
				field.Invalid(
					fldPath.Child("literalSubject"),
					"C=O,B=TX,CN=foo", "Literal subject contains unrecognized key with value [TX]"),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultMutableFeatureGate, feature.LiteralCertificateSubject, test.featureEnabled)
			errs, warnings := ValidateCertificate(test.a, test.cfg)
			assert.ElementsMatch(t, errs, test.errs)
			assert.ElementsMatch(t, warnings, []string{})
		})
	}
}
