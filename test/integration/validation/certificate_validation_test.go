/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/cert-manager/pkg/api"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha3"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/integration/framework"
)

var certGVK = schema.GroupVersionKind{
	Group:   "cert-manager.io",
	Version: "v1alpha3",
	Kind:    "Certificate",
}

func TestValidationCertificates(t *testing.T) {
	tests := map[string]struct {
		input       runtime.Object
		error       error
		expectError bool
	}{
		"certificate having too long common name": {
			input: &v1alpha3.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.CertificateSpec{
					SecretName: "something",
					CommonName: "testaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					IssuerRef:  cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: true,
			error:       errors.New(`Certificate.cert-manager.io "test" is invalid: spec.commonName: Invalid value: "": spec.commonName in body should be at most 64 chars long`),
		},
		"certificate missing secret name": {
			input: &v1alpha3.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.CertificateSpec{
					SecretName: "",
					IssuerRef:  cmmeta.ObjectReference{Name: "test"},
				},
			},
			expectError: true,
			error:       errors.New(`Certificate.cert-manager.io "test" is invalid: spec.secretName: Invalid value: "": spec.secretName in body should be at least 1 chars long`),
		},
		"certificate missing IssuerRef": {
			input: &v1alpha3.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.CertificateSpec{
					SecretName: "test",
					IssuerRef:  cmmeta.ObjectReference{},
				},
			},
			expectError: true,
			error:       errors.New(`Certificate.cert-manager.io "test" is invalid: spec.issuerRef.name: Invalid value: "": spec.issuerRef.name in body should be at least 1 chars long`),
		},
		"valid certificate with commonName exactly 64 bytes": {
			input: &v1alpha3.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.CertificateSpec{
					SecretName: "test",
					CommonName: "this-is-a-big-long-string-which-is-exactly-sixty-four-characters",
					IssuerRef:  cmmeta.ObjectReference{},
				},
			},
			expectError: false,
		},
		"valid wildcard certificate": {
			input: &v1alpha3.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.CertificateSpec{
					SecretName: "test",
					DNSNames: []string{
						"example.com",
						"*.example.com",
					},
					IssuerRef: cmmeta.ObjectReference{},
				},
			},
			expectError: false,
		},
		"valid certificate": {
			input: &v1alpha3.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha3.CertificateSpec{
					SecretName: "test",
					DNSNames: []string{
						"example.com",
						"www.example.com",
					},
					IssuerRef: cmmeta.ObjectReference{},
				},
			},
			expectError: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cert := test.input.(*v1alpha3.Certificate)
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

			if !test.expectError && err == nil {
				t.Fatalf("Didn't expect error and got error: %v", err)
			} else if test.expectError && err == nil {
				t.Errorf("Expected error %v but got nil", test.error)

			} else if test.expectError && err.Error() != test.error.Error() {
				t.Errorf("Expected error %v but got %v", test.error, err)
			}
		})
	}
}
