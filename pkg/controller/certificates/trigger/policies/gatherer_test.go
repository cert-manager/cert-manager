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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/test/unit/listers"
)

func TestDataForCertificate(t *testing.T) {
	tests := map[string]struct {
		name             string
		mockSecretLister *listers.FakeSecretLister
		mockListRequests func(t *testing.T) *listers.CertificateRequestListerMock
		givenCert        *cmapi.Certificate

		wantRequest *cmapi.CertificateRequest
		wantSecret  *corev1.Secret
		wantErr     string
	}{
		"the returned secret should stay nil when it is not found": {
			givenCert: certificate("uid-1", "secret-1", revision(nil)),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, apierrors.NewNotFound(cmapi.Resource("Secret"), "secret-1")),
			),
			mockListRequests: listers.CRNoop(),
			wantSecret:       nil,
		},
		"should return an error when getsecret returns an unexpect error that isnt not_found": {
			givenCert: certificate("uid-1", "secret-1", revision(nil)),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, fmt.Errorf("error that is not a not_found error")),
			),
			mockListRequests: listers.CRNoop(),
			wantErr:          "error that is not a not_found error",
		},
		"the returned certificaterequest should stay nil when the list function returns nothing": {
			givenCert: certificate("uid-1", "secret-1", revision(nil)),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockListRequests: listers.CRNoop(),
			wantRequest:      nil,
		},
		"should find the certificaterequest that matches revision and owner": {
			givenCert: certificate("uid-7", "secret-1", revision(ptr(7))),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockListRequests: listers.CRList("default", "", []*cmapi.CertificateRequest{
				certificateRequest("uid-4", "cert-manager.io/certificate-revision", "4"),
				certificateRequest("uid-7", "cert-manager.io/certificate-revision", "7"),
				certificateRequest("uid-9"),
			}, nil),
			wantRequest: certificateRequest("uid-7", "cert-manager.io/certificate-revision", "7"),
		},
		"should return a nil certificaterequest when no match of revision or owner": {
			givenCert: certificate("uid-1", "secret-1", revision(ptr(1))),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockListRequests: listers.CRList("default", "", []*cmapi.CertificateRequest{
				certificateRequest("uid-1"),
				certificateRequest("uid-1", "cert-manager.io/certificate-revision", "42"),
				certificateRequest("uid-42", "cert-manager.io/certificate-revision", "1"),
			}, nil),
			wantRequest: nil,
		},
		"should not return any certificaterequest when certificate has no revision yet": {
			givenCert: certificate("uid-1", "", revision(nil)),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockListRequests: listers.CRNoop(),
			wantRequest:      nil,
		},
		"should return the certificaterequest and secret and both found": {
			givenCert: certificate("uid-1", "secret-1", revision(ptr(1))),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-1"}}, nil),
			),
			mockListRequests: listers.CRList("default", "", []*cmapi.CertificateRequest{
				certificateRequest("uid-1", "cert-manager.io/certificate-revision", "1"),
			}, nil),
			wantRequest: certificateRequest("uid-1", "cert-manager.io/certificate-revision", "1"),
			wantSecret:  &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret-1"}},
		},
		"should return error when multiple certificaterequests found": {
			givenCert: certificate("uid-1", "secret-1", revision(ptr(1))),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockListRequests: listers.CRList("default", "", []*cmapi.CertificateRequest{
				certificateRequest("uid-1", "cert-manager.io/certificate-revision", "1"),
				certificateRequest("uid-1", "cert-manager.io/certificate-revision", "1"),
			}, nil),
			wantErr: "multiple CertificateRequest resources exist for the current revision, not triggering new issuance until requests have been cleaned up",
		},
		"should return error when the list func returns an error": {
			givenCert: certificate("uid-1", "secret-1", revision(ptr(1))),
			mockSecretLister: listers.FakeSecretListerFrom(listers.NewFakeSecretLister(),
				listers.SetFakeSecretNamespaceListerGet(nil, nil),
			),
			mockListRequests: listers.CRList("default", "", nil, fmt.Errorf("error that is not a not_found error")),
			wantErr:          "error that is not a not_found error",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			g := &Gatherer{
				CertificateRequestLister: test.mockListRequests(t),
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

// Unfortunately, pointer.IntPtr does not exist.
func ptr(i int) *int {
	return &i
}

type revision *int

func certificate(certUID, secretName string, revision revision) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", UID: types.UID(certUID)},
		Spec:       cmapi.CertificateSpec{SecretName: secretName},
		Status:     cmapi.CertificateStatus{Revision: revision},
	}
}

func certificateRequest(ownedUID string, annotationPairs ...string) *cmapi.CertificateRequest {
	annotations := make(map[string]string)
	for i := 0; i < len(annotationPairs); i += 2 {
		annotations[annotationPairs[i]] = annotationPairs[i+1]
	}
	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			OwnerReferences: []metav1.OwnerReference{{UID: types.UID(ownedUID), Controller: pointer.BoolPtr(true)}},
			Annotations:     annotations,
		},
	}
}
