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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/utils/pointer"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
)

func TestDataForCertificate(t *testing.T) {
	tests := []struct {
		name                       string
		mockSecretLister           func(t *testing.T) secretListerMock
		mockListRequests           func(t *testing.T) requestListerMock
		givenCrt                   *cmapi.Certificate
		wantCurrentRevisionRequest *cmapi.CertificateRequest
		wantSecret                 *corev1.Secret
		wantErr                    string
	}{
		{
			name:             "the returned secret should stay nil when it is not found",
			givenCrt:         &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "secret-1"}, ObjectMeta: metav1.ObjectMeta{Name: "a"}},
			mockSecretLister: mockSecretLister("default", "secret-1", nil, apierrors.NewNotFound(cmapi.Resource("Secret"), "secret-1")),
			mockListRequests: mockRequestLister("default", "", []*cmapi.CertificateRequest{}, nil),
			wantSecret:       nil,
		},
		{
			name:             "should return an error when getsecret returns an unexpected error that isnt not_found",
			givenCrt:         &cmapi.Certificate{Spec: cmapi.CertificateSpec{SecretName: "secret-1"}, ObjectMeta: metav1.ObjectMeta{Name: "a"}},
			mockSecretLister: mockSecretLister("default", "secret-1", nil, fmt.Errorf("some error from GetSecret that is not secret not found")),
			mockListRequests: mockRequestLister("default", "", []*cmapi.CertificateRequest{}, nil),
			wantErr:          "some error from GetSecret that is not secret not found",
		},
		{
			name:                       "the returned certificaterequest should stay nil when the list function returns nothing",
			givenCrt:                   &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Name: "mycert"}},
			mockSecretLister:           mockSecretLister("default", "", nil, nil),
			mockListRequests:           mockRequestLister("default", "", []*cmapi.CertificateRequest{}, nil),
			wantCurrentRevisionRequest: nil,
		},
		{
			name:             "should find the certificaterequest that matches revision and owner",
			givenCrt:         &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-7"}, Status: cmapi.CertificateStatus{Revision: ptr(7)}},
			mockSecretLister: mockSecretLister("default", "", nil, nil),
			mockListRequests: mockRequestLister("default", "", []*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-4", Controller: pointer.BoolPtr(true)}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "4"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-7", Controller: pointer.BoolPtr(true)}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "7"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-9", Controller: pointer.BoolPtr(true)}}}},
			}, nil),
			wantCurrentRevisionRequest: &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-7", Controller: pointer.BoolPtr(true)}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "7"}},
			},
		},
		{
			name:             "should return a nil certificaterequest when no match of revision or owner",
			givenCrt:         &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}, Status: cmapi.CertificateStatus{Revision: ptr(1)}},
			mockSecretLister: mockSecretLister("default", "", nil, nil),
			mockListRequests: mockRequestLister("default", "", []*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "2"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1"}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-42"}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
			}, nil),
			wantCurrentRevisionRequest: nil,
		},
		{
			name:             "should not return any certificaterequest when certificate has no revision yet",
			givenCrt:         &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}, Status: cmapi.CertificateStatus{Revision: nil}},
			mockSecretLister: mockSecretLister("default", "", nil, nil),
			mockListRequests: mockRequestLister("default", "", []*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "2"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}}}},
			}, nil),
			wantCurrentRevisionRequest: nil,
		},
		{
			name: "should return the certificaterequest and secret and both found",
			givenCrt: &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{UID: "uid-1"},
				Spec:       cmapi.CertificateSpec{SecretName: "secret-1"},
				Status:     cmapi.CertificateStatus{Revision: ptr(1)},
			},
			mockSecretLister: mockSecretLister("default", "secret-1", &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-1"}}, nil),
			mockListRequests: mockRequestLister("default", "", []*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}},
					Annotations:     map[string]string{"cert-manager.io/certificate-revision": "1"}},
				},
			}, nil),
			wantCurrentRevisionRequest: &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}},
				Annotations:     map[string]string{"cert-manager.io/certificate-revision": "1"}},
			},
			wantSecret: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-1"}},
		},
		{
			name:             "should return error when multiple certificaterequests found",
			givenCrt:         &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}, Status: cmapi.CertificateStatus{Revision: ptr(1)}},
			mockSecretLister: mockSecretLister("default", "", nil, nil),
			mockListRequests: mockRequestLister("default", "", []*cmapi.CertificateRequest{
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
				{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{{UID: "uid-1", Controller: pointer.BoolPtr(true)}}, Annotations: map[string]string{"cert-manager.io/certificate-revision": "1"}}},
			}, nil),
			wantErr: "multiple CertificateRequest resources exist for the current revision, not triggering new issuance until requests have been cleaned up",
		},
		{
			name:             "should return error when the list func returns an error",
			givenCrt:         &cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}, Status: cmapi.CertificateStatus{Revision: ptr(1)}},
			mockSecretLister: mockSecretLister("default", "", nil, nil),
			mockListRequests: mockRequestLister("default", "", []*cmapi.CertificateRequest{}, fmt.Errorf("some error from certificates.List that is not not_found")),
			wantErr:          "some error from certificates.List that is not not_found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Gatherer{
				CertificateRequestLister: tt.mockListRequests(t),
				SecretLister:             tt.mockSecretLister(t),
			}

			got, gotErr := g.DataForCertificate(context.Background(), tt.givenCrt)

			if tt.wantErr != "" {
				assert.Error(t, gotErr)
				assert.EqualError(t, gotErr, tt.wantErr)
				return
			}

			require.NoError(t, gotErr)
			assert.Equal(t, tt.wantCurrentRevisionRequest, got.CurrentRevisionRequest)
			assert.Equal(t, tt.wantSecret, got.Secret)
			assert.Equal(t, tt.givenCrt, got.Certificate, "input cert should always be equal to returned cert")
		})
	}
}

// Unfortunately, pointer.IntPtr does not exist.
func ptr(i int) *int {
	return &i
}

type requestListerNamespacedMock struct {
	t                      *testing.T
	expectedListSelector   string
	returnListCertRequests []*cmapi.CertificateRequest
	returnListErr          error
}

type requestListerMock struct {
	t                             *testing.T
	expectedNamespace             string
	returnRequestListerNamespaced requestListerNamespacedMock
}

func (mock requestListerMock) List(selector labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	mock.t.Error("not expected to be called")
	return nil, nil
}

func (mock requestListerMock) CertificateRequests(namespace string) cmlisters.CertificateRequestNamespaceLister {
	return mock.returnRequestListerNamespaced
}

func (mock requestListerNamespacedMock) List(got labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	assert.Equal(mock.t, mock.expectedListSelector, got.String())
	return mock.returnListCertRequests, mock.returnListErr
}

func (mock requestListerNamespacedMock) Get(name string) (cr *cmapi.CertificateRequest, e error) {
	mock.t.Error("not expected to be called")
	return nil, nil
}

// The expectedSelector is a label selector of the form:
//     partition in (customerA, customerB),environment!=qa
// as detailed in
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
func mockRequestLister(expectedNamespace, expectedSelector string, returnList []*cmapi.CertificateRequest, returnListErr error) func(*testing.T) requestListerMock {
	return func(t *testing.T) requestListerMock {
		return requestListerMock{
			t:                             t,
			expectedNamespace:             expectedNamespace,
			returnRequestListerNamespaced: requestListerNamespacedMock{t: t, expectedListSelector: expectedSelector, returnListCertRequests: returnList, returnListErr: returnListErr},
		}
	}
}

type secretListerMock struct {
	t                               *testing.T
	expectedNamespace               string
	returnSecretNamespaceListerMock secretNamespaceListerMock
}

func (mock secretListerMock) List(selector labels.Selector) (ret []*v1.Secret, err error) {
	mock.t.Error("not expected to be called")
	return nil, nil
}
func (mock secretListerMock) Secrets(namespace string) corelisters.SecretNamespaceLister {
	return mock.returnSecretNamespaceListerMock
}

type secretNamespaceListerMock struct {
	t               *testing.T
	expectedGetName string
	returnGetSecret *v1.Secret
	returnGetErr    error
}

func (mock secretNamespaceListerMock) List(selector labels.Selector) (ret []*v1.Secret, err error) {
	mock.t.Error("not expected to be called")
	return nil, nil
}

func (mock secretNamespaceListerMock) Get(name string) (*v1.Secret, error) {
	assert.Equal(mock.t, mock.expectedGetName, name)
	return mock.returnGetSecret, mock.returnGetErr
}

func mockSecretLister(expectedNamespace string, expectedName string, returnSecret *v1.Secret, returnGetErr error) func(*testing.T) secretListerMock {
	return func(t *testing.T) secretListerMock {
		return secretListerMock{
			t:                               t,
			expectedNamespace:               expectedNamespace,
			returnSecretNamespaceListerMock: secretNamespaceListerMock{t: t, expectedGetName: expectedName, returnGetSecret: returnSecret, returnGetErr: returnGetErr},
		}
	}
}
