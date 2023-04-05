/*
Copyright 2022 The cert-manager Authors.

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
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	"github.com/cert-manager/cert-manager/pkg/api"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

var certificateGVK = schema.GroupVersionKind{
	Group:   "cert-manager.io",
	Version: "v1",
	Kind:    "Certificate",
}

func TestValidationCertificate(t *testing.T) {
	tests := map[string]struct {
		input       runtime.Object
		errorSuffix string
		expectError bool
	}{
		"Happy path returns no errors": {
			input: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testing",
					Namespace: "default",
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testing-tls",
					DNSNames:   []string{"myhostname.com"},
					Usages:     []cmapi.KeyUsage{},
					IssuerRef: cmmeta.ObjectReference{
						Name: "letsencrypt-staging",
					},
					PrivateKey: &cmapi.CertificatePrivateKey{
						RotationPolicy: "Always",
					},
				},
			},
			expectError: false,
		},
		"Bad value for certificate.spec.privateKey.rotationPolicy returns error": {
			input: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testing",
					Namespace: "default",
				},
				Spec: cmapi.CertificateSpec{
					SecretName: "testing-tls",
					DNSNames:   []string{"myhostname.com"},
					Usages:     []cmapi.KeyUsage{},
					IssuerRef: cmmeta.ObjectReference{
						Name: "letsencrypt-staging",
					},
					PrivateKey: &cmapi.CertificatePrivateKey{
						RotationPolicy: "Alway!",
					},
				},
			},
			errorSuffix: "supported values: \"Never\", \"Always\"",
			expectError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cert := test.input.(*cmapi.Certificate)
			cert.SetGroupVersionKind(certificateGVK)

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
			defer cancel()

			config, stop := framework.RunControlPlane(t, ctx)
			defer stop()

			framework.WaitForOpenAPIResourcesToBeLoaded(t, ctx, config, certificateGVK)

			cl, err := client.New(config, client.Options{Scheme: api.Scheme})
			if err != nil {
				t.Fatal(err)
			}

			err = cl.Create(ctx, cert)

			if test.expectError {
				if err == nil {
					t.Error("expected an error, got nil")
				}

				if !strings.HasSuffix(err.Error(), test.errorSuffix) {
					t.Errorf("expected error with suffix \"%v\", got error: \"%v\"", test.errorSuffix, err)
				}
			}

			if !test.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
