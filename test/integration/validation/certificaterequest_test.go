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
	"context"
	"encoding/pem"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/pkg/api"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/integration/framework"
)

var certGVK = schema.GroupVersionKind{
	Group:   "cert-manager.io",
	Version: "v1",
	Kind:    "CertificateRequest",
}

func TestValidationCertificateRequests(t *testing.T) {
	tests := map[string]struct {
		input       runtime.Object
		errorSuffix string // is a suffix as the API server sends the whole value back in the error
		expectError bool
	}{
		"No errors on valid certificaterequest with no usages set": {
			input: &v1.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &v1.Certificate{
						Spec: v1.CertificateSpec{
							DNSNames: []string{"example.com"},
						},
					}),
					Usages:    []v1.KeyUsage{},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: false,
		},
		"No errors on valid certificaterequest with special usages set": {
			input: &v1.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &v1.Certificate{
						Spec: v1.CertificateSpec{
							DNSNames: []string{"example.com"},
							Usages:   []v1.KeyUsage{v1.UsageDigitalSignature, v1.UsageKeyEncipherment, v1.UsageClientAuth},
						},
					}),
					Usages:    []v1.KeyUsage{v1.UsageDigitalSignature, v1.UsageKeyEncipherment, v1.UsageClientAuth},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: false,
		},
		"No errors on valid certificaterequest with special usages set only in CSR": {
			input: &v1.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &v1.Certificate{
						Spec: v1.CertificateSpec{
							DNSNames: []string{"example.com"},
							Usages:   []v1.KeyUsage{v1.UsageDigitalSignature, v1.UsageKeyEncipherment, v1.UsageClientAuth},
						},
					}),
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: false,
		},
		"No errors on valid certificaterequest with special usages only set in spec": {
			input: &v1.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &v1.Certificate{
						Spec: v1.CertificateSpec{
							DNSNames: []string{"example.com"},
							Usages:   []v1.KeyUsage{},
						},
					}),
					Usages:    []v1.KeyUsage{v1.UsageDigitalSignature, v1.UsageKeyEncipherment, v1.UsageClientAuth},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: false,
		},
		"Errors on certificaterequest with mismatch of usages": {
			input: &v1.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &v1.Certificate{
						Spec: v1.CertificateSpec{
							DNSNames: []string{"example.com"},
							Usages:   []v1.KeyUsage{v1.UsageDigitalSignature, v1.UsageKeyEncipherment, v1.UsageClientAuth},
						},
					}),
					Usages:    []v1.KeyUsage{v1.UsageDigitalSignature, v1.UsageKeyEncipherment, v1.UsageCodeSigning},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: true,
			errorSuffix: "csr key usages do not match specified usages, these should match if both are set: [[2]: \"client auth\" != \"code signing\"]",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cert := test.input.(*v1.CertificateRequest)
			cert.SetGroupVersionKind(certGVK)

			config, stop := framework.RunControlPlane(t)
			defer stop()
			framework.WaitForOpenAPIResourcesToBeLoaded(t, config, certGVK)

			// create the object to get any errors back from the webhook
			cl, err := client.New(config, client.Options{Scheme: api.Scheme})
			if err != nil {
				t.Fatal(err)
			}

			err = cl.Create(context.Background(), cert)

			if !test.expectError && err != nil {
				t.Fatalf("Didn't expect error and got error: %v", err)
			} else if test.expectError && err == nil {
				t.Errorf("Expected error %v but got nil", test.errorSuffix)

			} else if test.expectError && !strings.HasSuffix(err.Error(), test.errorSuffix) {
				t.Errorf("Expected error %q but got %q", test.errorSuffix, err)
			}
		})
	}
}

func mustGenerateCSR(t *testing.T, cert *v1.Certificate) []byte {
	request, err := pki.GenerateCSR(cert)
	if err != nil {
		t.Fatal(err)
	}

	sk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csrBytes, err := pki.EncodeCSR(request, sk)
	if err != nil {
		t.Fatal(err)
	}
	csr := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})

	return csr
}
