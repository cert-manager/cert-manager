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

package certificates

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmv1listers "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
)

func TestCertificateOwnsSecret(t *testing.T) {
	testNamespace := "test-namespace"
	testSecretName := "test-secret"
	testCreationTimestamp := time.Now()

	certificate := func(name string, creationTimestamp time.Time) *cmapi.Certificate {
		return &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:              name,
				Namespace:         testNamespace,
				CreationTimestamp: metav1.Time{Time: creationTimestamp},
			},
			Spec: cmapi.CertificateSpec{
				SecretName: testSecretName,
			},
		}
	}

	tests := []struct {
		name string

		selectedCertificate string
		secrets             []runtime.Object
		certificates        []runtime.Object

		expectedResult      bool
		expectedOtherOwners []string
		expectedError       error
	}{
		{
			name: "Certificate is only cert referencing the secret",

			selectedCertificate: "certificate-1",
			secrets:             []runtime.Object{},
			certificates: []runtime.Object{
				certificate("certificate-1", testCreationTimestamp),
			},

			expectedResult:      true,
			expectedOtherOwners: nil,
			expectedError:       nil,
		},
		{
			name: "Certificate has conflict, but is the oldest",

			selectedCertificate: "certificate-3",
			secrets:             []runtime.Object{},
			certificates: []runtime.Object{
				certificate("certificate-3", testCreationTimestamp),
				certificate("certificate-2", testCreationTimestamp.Add(1*time.Second)),
				certificate("certificate-1", testCreationTimestamp.Add(1*time.Second)),
			},

			expectedResult:      true,
			expectedOtherOwners: []string{"certificate-1", "certificate-2"},
			expectedError:       nil,
		},
		{
			name: "Certificate has conflict, but has alphabetically lower name",

			selectedCertificate: "certificate-1",
			secrets:             []runtime.Object{},
			certificates: []runtime.Object{
				certificate("certificate-1", testCreationTimestamp),
				certificate("certificate-2", testCreationTimestamp),
				certificate("certificate-3", testCreationTimestamp),
			},

			expectedResult:      true,
			expectedOtherOwners: []string{"certificate-2", "certificate-3"},
			expectedError:       nil,
		},
		{
			name: "Certificate has conflict, but annotation marks it as the owner",

			selectedCertificate: "certificate-3",
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testNamespace,
						Annotations: map[string]string{
							cmapi.CertificateNameKey: "certificate-3",
						},
					},
				},
			},
			certificates: []runtime.Object{
				certificate("certificate-1", testCreationTimestamp),
				certificate("certificate-2", testCreationTimestamp),
				certificate("certificate-3", testCreationTimestamp),
			},

			expectedResult:      true,
			expectedOtherOwners: []string{"certificate-1", "certificate-2"},
			expectedError:       nil,
		},
		{
			name: "Certificate has conflict, is the oldest, but annotation marks another as the owner",

			selectedCertificate: "certificate-3",
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testNamespace,
						Annotations: map[string]string{
							cmapi.CertificateNameKey: "certificate-2",
						},
					},
				},
			},
			certificates: []runtime.Object{
				certificate("certificate-3", testCreationTimestamp),
				certificate("certificate-2", testCreationTimestamp.Add(1*time.Second)),
				certificate("certificate-1", testCreationTimestamp.Add(1*time.Second)),
			},

			expectedResult:      false,
			expectedOtherOwners: []string{"certificate-1", "certificate-2"},
			expectedError:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake certificate lister
			certIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
				cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
			})
			for _, crt := range tt.certificates {
				if err := certIndexer.Add(crt); err != nil {
					t.Fatal(err)
				}
			}
			certificateLister := cmv1listers.NewCertificateLister(certIndexer)

			// Create a fake secret lister
			secretIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
				cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
			})
			for _, secret := range tt.secrets {
				if err := secretIndexer.Add(secret); err != nil {
					t.Fatal(err)
				}
			}
			secretLister := corev1listers.NewSecretLister(secretIndexer)

			// Find the selected Certificate
			var selectedCrt *cmapi.Certificate
			for _, crt := range tt.certificates {
				if crt.(*cmapi.Certificate).Name == tt.selectedCertificate {
					selectedCrt = crt.(*cmapi.Certificate)
					break
				}
			}
			if selectedCrt == nil {
				t.Fatal("failed to find selected Certificate")
			}

			// Call the function under test
			result, owners, err := CertificateOwnsSecret(context.TODO(), certificateLister, secretLister, selectedCrt)

			// Verify the result
			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedOtherOwners, owners)
			assert.Equal(t, tt.expectedError, err)
		})
	}
}
