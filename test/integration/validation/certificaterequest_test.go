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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	"github.com/cert-manager/cert-manager/pkg/api"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
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
			input: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: cmapi.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &cmapi.Certificate{
						Spec: cmapi.CertificateSpec{
							DNSNames: []string{"example.com"},
						},
					}),
					Usages:    []cmapi.KeyUsage{},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: false,
		},
		"No errors on valid certificaterequest with special usages set": {
			input: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: cmapi.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &cmapi.Certificate{
						Spec: cmapi.CertificateSpec{
							DNSNames: []string{"example.com"},
							Usages:   []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth},
						},
					}),
					Usages:    []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: false,
		},
		"No errors on valid certificaterequest with special usages set only in CSR": {
			input: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: cmapi.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &cmapi.Certificate{
						Spec: cmapi.CertificateSpec{
							DNSNames: []string{"example.com"},
							Usages:   []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth},
						},
					}),
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: true,
			errorSuffix: "encoded CSR error: the ExtKeyUsages [ 'client auth' ] do not match the expected ExtKeyUsages []",
		},
		"No errors on valid certificaterequest with special usages only set in spec": {
			input: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: cmapi.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &cmapi.Certificate{
						Spec: cmapi.CertificateSpec{
							DNSNames:              []string{"example.com"},
							Usages:                []cmapi.KeyUsage{},
							EncodeUsagesInRequest: ptr.To(false),
						},
					}),
					Usages:    []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: false,
		},
		"Errors on certificaterequest with mismatch of usages": {
			input: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: cmapi.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &cmapi.Certificate{
						Spec: cmapi.CertificateSpec{
							DNSNames: []string{"example.com"},
							Usages:   []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth},
						},
					}),
					Usages:    []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageCodeSigning},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: true,
			errorSuffix: "encoded CSR error: the ExtKeyUsages [ 'client auth' ] do not match the expected ExtKeyUsages [ 'code signing' ]",
		},
		"Shouldn't error when setting user info, since this will be overwritten by the mutating webhook": {
			input: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: cmapi.CertificateRequestSpec{
					Request: mustGenerateCSR(t, &cmapi.Certificate{
						Spec: cmapi.CertificateSpec{
							DNSNames:              []string{"example.com"},
							Usages:                []cmapi.KeyUsage{},
							EncodeUsagesInRequest: ptr.To(false),
						},
					}),
					Usages:    []cmapi.KeyUsage{cmapi.UsageDigitalSignature, cmapi.UsageKeyEncipherment, cmapi.UsageClientAuth},
					IssuerRef: cmmeta.ObjectReference{Name: "test"},
					Username:  "user-1",
					Groups:    []string{"group-1", "group-2"},
				},
			},
			expectError: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cert := test.input.(*cmapi.CertificateRequest)
			cert.SetGroupVersionKind(certGVK)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
			defer cancel()

			config, stop := framework.RunControlPlane(t, ctx)
			defer stop()

			framework.WaitForOpenAPIResourcesToBeLoaded(t, ctx, config, certGVK)

			// create the object to get any errors back from the webhook
			cl, err := client.New(config, client.Options{Scheme: api.Scheme})
			if err != nil {
				t.Fatal(err)
			}

			err = cl.Create(ctx, cert)
			if test.expectError != (err != nil) {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expectError, err)
			}
			if test.expectError && !strings.HasSuffix(err.Error(), test.errorSuffix) {
				t.Errorf("unexpected error suffix, exp=%s got=%s",
					test.errorSuffix, err)
			}
		})
	}
}

func mustGenerateCSR(t *testing.T, cert *cmapi.Certificate) []byte {
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
