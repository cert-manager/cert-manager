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

package conversion

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/jetstack/cert-manager/pkg/util/pki"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/cert-manager/pkg/api"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha3"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/integration/framework"
)

func generateCSR(t *testing.T) []byte {
	skRSA, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, skRSA)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

func TestConversion(t *testing.T) {
	tests := map[string]struct {
		input  runtime.Object
		output runtime.Object
	}{
		"should convert Certificates from v1alpha2 to v1alpha3": {
			input: &v1alpha2.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha2.CertificateSpec{
					SecretName: "something",
					CommonName: "test",
					IssuerRef: cmmeta.ObjectReference{
						Name: "issuername",
					},
				},
			},
			output: &v1alpha3.Certificate{},
		},
		"should convert CertificateRequest from v1alpha2 to v1alpha3": {
			input: &v1alpha2.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v1alpha2.CertificateRequestSpec{
					// validating webhook isn't currently configured in test
					// environment so this passes validation.
					CSRPEM: generateCSR(t),
					IssuerRef: cmmeta.ObjectReference{
						Name: "issuername",
					},
				},
			},
			output: &v1alpha3.CertificateRequest{},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config, stop := framework.RunControlPlane(t)
			defer stop()

			cl, err := client.New(config, client.Options{Scheme: api.Scheme})
			if err != nil {
				t.Fatal(err)
			}

			if err := cl.Create(context.Background(), test.input); err != nil {
				t.Fatal(err)
			}
			meta := test.input.(metav1.ObjectMetaAccessor)
			if err := cl.Get(context.Background(), client.ObjectKey{Name: meta.GetObjectMeta().GetName(), Namespace: meta.GetObjectMeta().GetNamespace()}, test.output); err != nil {
				t.Errorf("failed to fetch object in expected API version: %v", err)
			}
		})
	}
}
