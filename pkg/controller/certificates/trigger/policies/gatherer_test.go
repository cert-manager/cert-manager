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

package policies

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlist "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/jetstack/cert-manager/test/unit/listers"
)

func TestDataForCertificate(t *testing.T) {
	tests := map[string]struct {
		name             string
		mockSecretLister *listers.FakeSecretLister
		givenCert        *cmapi.Certificate

		mockCertificateRequestsLister func(*testing.T) *listers.FakeCertificateRequestLister
		wantRequest                   *cmapi.CertificateRequest
		wantSecret                    *corev1.Secret
		wantErr                       string
	}{
		"the returned secret should stay nil when it is not found": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateUID("uid-1"),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, apierrors.NewNotFound(cmapi.Resource("Secret"), "secret-1")),
			),
			mockCertificateRequestsLister: expectNeverCalled(),
			wantSecret:                    nil,
		},
		"should return an error when getsecret returns an unexpect error that isnt not_found": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateUID("uid-1"),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, fmt.Errorf("error that is not a not_found error")),
			),
			mockCertificateRequestsLister: expectNeverCalled(),
			wantErr:                       "error that is not a not_found error",
		},
		"the returned certificaterequest should stay nil when the list function returns nothing": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateUID("uid-1"),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockCertificateRequestsLister: expectNeverCalled(),
			wantRequest:                   nil,
		},
		"should find the certificaterequest that matches revision and owner": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateUID("uid-7"),
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateRevision(7),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockCertificateRequestsLister: mockCertificateRequests("default-unit-test-ns", func(t *testing.T) *listers.FakeCertificateRequestNamespaceLister {
				f := expectCalled(t, 1)
				return listers.NewFakeCertificateRequestNamespaceLister().WithList(func(_ labels.Selector) ([]*cmapi.CertificateRequest, error) {
					f()
					return []*cmapi.CertificateRequest{
						gen.CertificateRequest("cr-4",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-4")),
							gen.AddCertificateRequestAnnotations(map[string]string{
								"cert-manager.io/certificate-revision": "4",
							}),
						),
						gen.CertificateRequest("cr-7",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-7")),
							gen.AddCertificateRequestAnnotations(map[string]string{
								"cert-manager.io/certificate-revision": "7",
							}),
						),
						gen.CertificateRequest("cr-9",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-9")),
						),
					}, nil
				})
			}),
			wantRequest: gen.CertificateRequest("cr-7",
				gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-7")),
				gen.AddCertificateRequestAnnotations(map[string]string{
					"cert-manager.io/certificate-revision": "7",
				}),
			),
		},
		"should return a nil certificaterequest when no match of revision or owner": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateUID("uid-1"),
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateRevision(1),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockCertificateRequestsLister: mockCertificateRequests("default-unit-test-ns", func(t *testing.T) *listers.FakeCertificateRequestNamespaceLister {
				f := expectCalled(t, 1)
				return listers.NewFakeCertificateRequestNamespaceLister().WithList(func(_ labels.Selector) ([]*cmapi.CertificateRequest, error) {
					f()
					return []*cmapi.CertificateRequest{
						gen.CertificateRequest("cr-1",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-1")),
						),
						gen.CertificateRequest("cr-1",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-1")),
							gen.AddCertificateRequestAnnotations(map[string]string{
								"cert-manager.io/certificate-revision": "42",
							}),
						),
						gen.CertificateRequest("cr-42",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-42", "uid-42")),
							gen.AddCertificateRequestAnnotations(map[string]string{
								"cert-manager.io/certificate-revision": "1",
							}),
						),
					}, nil
				})
			}),
			wantRequest: nil,
		},
		"should not return any certificaterequest when certificate has no revision yet": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateUID("uid-1"),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockCertificateRequestsLister: expectNeverCalled(),
			wantRequest:                   nil,
		},
		"should return the certificaterequest and secret and both found": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateUID("uid-1"),
				gen.SetCertificateRevision(1),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-1"}}, nil),
			),
			mockCertificateRequestsLister: mockCertificateRequests("default-unit-test-ns", func(t *testing.T) *listers.FakeCertificateRequestNamespaceLister {
				f := expectCalled(t, 1)
				return listers.NewFakeCertificateRequestNamespaceLister().WithList(func(_ labels.Selector) ([]*cmapi.CertificateRequest, error) {
					f()
					return []*cmapi.CertificateRequest{
						gen.CertificateRequest("cr-1",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-1")),
							gen.AddCertificateRequestAnnotations(map[string]string{
								"cert-manager.io/certificate-revision": "1",
							}),
						),
					}, nil
				})
			}),
			wantRequest: gen.CertificateRequest("cr-1",
				gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-1")),
				gen.AddCertificateRequestAnnotations(map[string]string{
					"cert-manager.io/certificate-revision": "1",
				}),
			),
			wantSecret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-1"}},
		},
		"should return error when multiple certificaterequests found": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateUID("uid-1"),
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateRevision(1),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockCertificateRequestsLister: mockCertificateRequests("default-unit-test-ns", func(t *testing.T) *listers.FakeCertificateRequestNamespaceLister {
				f := expectCalled(t, 1)
				return listers.NewFakeCertificateRequestNamespaceLister().WithList(func(_ labels.Selector) ([]*cmapi.CertificateRequest, error) {
					f()
					return []*cmapi.CertificateRequest{
						gen.CertificateRequest("cr-1",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-1")),
							gen.AddCertificateRequestAnnotations(map[string]string{
								"cert-manager.io/certificate-revision": "1",
							}),
						),
						gen.CertificateRequest("cr-1",
							gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-1")),
							gen.AddCertificateRequestAnnotations(map[string]string{
								"cert-manager.io/certificate-revision": "1",
							}),
						)}, nil
				})
			}),
			wantErr: "multiple CertificateRequest resources exist for the current revision, not triggering new issuance until requests have been cleaned up",
		},
		"should return error when the list func returns an error": {
			givenCert: gen.Certificate("cert-1",
				gen.SetCertificateUID("uid-1"),
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateRevision(1),
			),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(&corev1.Secret{}, nil),
			),
			mockCertificateRequestsLister: mockCertificateRequests("default-unit-test-ns", func(t *testing.T) *listers.FakeCertificateRequestNamespaceLister {
				f := expectCalled(t, 1)
				return listers.NewFakeCertificateRequestNamespaceLister().WithList(func(_ labels.Selector) ([]*cmapi.CertificateRequest, error) {
					f()
					return nil, fmt.Errorf("error that is not a not_found error")
				})
			}),
			wantErr: "error that is not a not_found error",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			g := &Gatherer{
				CertificateRequestLister: test.mockCertificateRequestsLister(t),
				SecretLister:             test.mockSecretLister,
			}

			got, gotErr := g.DataForCertificate(context.Background(), test.givenCert)

			if test.wantErr != "" {
				assert.Error(t, gotErr)
				assert.EqualError(t, gotErr, test.wantErr)
				return
			}

			require.NoError(t, gotErr)
			assert.Equal(t, test.wantRequest, got.CurrentRevisionRequest)
			assert.Equal(t, test.wantSecret, got.Secret)
			assert.Equal(t, test.givenCert, got.Certificate, "input cert should always be equal to returned cert")
		})
	}
}

// Creates a mock CertificateRequestLister.
//
// We want to use a mock instead of a fake here: the mock makes sure that
// (1) the lister.CertificateRequests(namespace) has been called with the
// correct expected namespace and (2) lister.CertificateRequests(namespace)
// has been called exactly once, which makes sure (1) was checked.
func mockCertificateRequests(expNamespace string, innerLister func(t *testing.T) *listers.FakeCertificateRequestNamespaceLister) func(*testing.T) *listers.FakeCertificateRequestLister {
	return func(t *testing.T) *listers.FakeCertificateRequestLister {
		f := expectCalled(t, 1)
		return listers.
			NewFakeCertificateRequestLister().
			WithCertificateRequests(func(namespace string) cmlist.CertificateRequestNamespaceLister {
				f()
				assert.Equal(t, expNamespace, namespace)
				return innerLister(t)
			})
	}
}

// The returned function f is expected to be called expectedCount times.
// Returns a friendly error with the location where f was created to help
// the developer figure out where the error came from.
func expectCalled(t *testing.T, expectedCount uint32) (f func()) {
	// Debugging purposes: allows us to display where this function was
	// called. The reason we need to to this is because t.Cleanup's stack
	// does not contain the origin function, which makes it really hard to
	// know where the assertion failed.
	stack := grandparentStack(2)

	gotCount := uint32(0)
	t.Cleanup(func() {
		assert.Equal(t, int(expectedCount), int(atomic.LoadUint32(&gotCount)), "this func was expected to be called %d times but was called %d times. Stack:\n\t%s",
			expectedCount,
			gotCount,
			strings.Join(stack, "\n\t"),
		)
	})
	return func() {
		atomic.AddUint32(&gotCount, 1)
	}
}

func expectNeverCalled() func(t *testing.T) *listers.FakeCertificateRequestLister {
	return func(t *testing.T) *listers.FakeCertificateRequestLister {
		f := expectCalled(t, 0)
		return listers.NewFakeCertificateRequestLister().WithCertificateRequests(func(namespace string) cmlist.CertificateRequestNamespaceLister {
			f()
			return nil
		})
	}
}

// Returns the stack of the callers of the form "file.go:93". The N first
// items are skipped. The stack stops as soon as it meets a function in
// testing.go since we are not interested by those.
func grandparentStack(skip int) []string {
	var stack []string
	for i := skip; ; i++ {
		_, file, line, ok := runtime.Caller(i)
		file = filepath.Base(file)
		if file == "testing.go" || !ok {
			break
		}
		stack = append(stack, fmt.Sprintf("%s:%d", file, line))
	}
	return stack
}
