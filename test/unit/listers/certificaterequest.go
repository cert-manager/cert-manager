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

// These mock listers make sure that the given call, e.g. with CRList,
//
//   lister.CertificateRequest("default").Get("cr-1")
//
// is called exactly once. The major limitation of these mock listers is
// that they only account for one or zero call to the Get and List
// functions, which is fine in our tests.

package listers

import (
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlist "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
)

func CRNoop() func(*testing.T) *CertificateRequestListerMock {
	return func(t *testing.T) *CertificateRequestListerMock {
		return &CertificateRequestListerMock{
			t:                     t,
			returnNamespaceLister: &CertificateRequestListerNamespacedMock{t: t},
		}
	}
}

// The expectSelector is a label selector of the form:
//     partition in (customerA, customerB),environment!=qa
// as detailed in
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
func CRList(expectNamespace, expectSelector string, returnList []*cmapi.CertificateRequest, returnListErr error) func(*testing.T) *CertificateRequestListerMock {
	return func(t *testing.T) *CertificateRequestListerMock {
		mock := &CertificateRequestListerMock{t: t,
			expectNamespaceCalled: true,
			expectNamespace:       expectNamespace,
			returnNamespaceLister: &CertificateRequestListerNamespacedMock{t: t,
				expectListCalled:   true,
				expectListSelector: expectSelector,
				returnList:         returnList,
				returnListErr:      returnListErr,
			},
		}
		t.Cleanup(func() {
			assert.True(t, mock.gotNamespaceCalled, "CertificateRequest was expected to be called but was not")
			assert.True(t, mock.returnNamespaceLister.gotListCalled, "CertificateRequest.List was expected to be called but was not")
		})
		return mock
	}
}

// The expectSelector is a label selector of the form:
//     partition in (customerA, customerB),environment!=qa
// as detailed in
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
func CRUnnamespacedList(expectSelector string, returnList []*cmapi.CertificateRequest, returnListErr error) func(*testing.T) *CertificateRequestListerMock {
	return func(t *testing.T) *CertificateRequestListerMock {
		mock := &CertificateRequestListerMock{t: t,
			expectListCalled:   true,
			expectListSelector: expectSelector,
			returnList:         returnList,
			returnListErr:      returnListErr,
		}
		t.Cleanup(func() {
			assert.True(t, mock.gotListCalled, "CertificateRequest List (unnamespaced) was expected to be called but was not")
		})
		return mock
	}
}

func CRGet(expectNamespace, expectGetName string, returnGet *cmapi.CertificateRequest, returnGetErr error) func(*testing.T) *CertificateRequestListerMock {
	return func(t *testing.T) *CertificateRequestListerMock {
		mock := &CertificateRequestListerMock{t: t,
			expectNamespaceCalled: true,
			expectNamespace:       expectNamespace,
			returnNamespaceLister: &CertificateRequestListerNamespacedMock{t: t,
				expectGetCalled: true,
				expectGetName:   expectGetName,
				returnGet:       returnGet,
				returnGetErr:    returnGetErr,
			},
		}
		t.Cleanup(func() {
			assert.True(t, mock.gotNamespaceCalled, "CertificateRequest was expected to be called but was not")
			assert.True(t, mock.returnNamespaceLister.gotGetCalled, "CertificateRequest.Get was expected to be called but was not")
		})
		return mock
	}
}

type CertificateRequestListerMock struct {
	t  *testing.T
	mu sync.Mutex

	expectNamespaceCalled, gotNamespaceCalled bool
	expectNamespace                           string
	returnNamespaceLister                     *CertificateRequestListerNamespacedMock

	expectListCalled, gotListCalled bool
	expectListSelector              string
	returnList                      []*cmapi.CertificateRequest
	returnListErr                   error
}

func (mock *CertificateRequestListerMock) CertificateRequests(gotNamespace string) cmlist.CertificateRequestNamespaceLister {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.True(mock.t, mock.expectNamespaceCalled, fnName()+" not expected to be called")
	require.False(mock.t, mock.gotNamespaceCalled, fnName()+" already called once before")
	assert.Equal(mock.t, mock.expectNamespace, gotNamespace)
	mock.gotNamespaceCalled = true
	return mock.returnNamespaceLister
}

func (mock *CertificateRequestListerMock) List(gotLabel labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.True(mock.t, mock.expectListCalled, fnName()+" not expected to be called")
	require.False(mock.t, mock.gotListCalled, fnName()+" already called once before")
	assert.Equal(mock.t, mock.expectListSelector, gotLabel.String())
	mock.gotListCalled = true
	return mock.returnList, mock.returnListErr
}

type CertificateRequestListerNamespacedMock struct {
	t  *testing.T
	mu sync.Mutex

	expectGetCalled, gotGetCalled bool
	expectGetName                 string
	returnGet                     *cmapi.CertificateRequest
	returnGetErr                  error

	expectListCalled, gotListCalled bool
	expectListSelector              string
	returnList                      []*cmapi.CertificateRequest
	returnListErr                   error
}

func (mock *CertificateRequestListerNamespacedMock) List(got labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.NotNil(mock.t, mock.expectListCalled, fnName()+" not expected to be called")
	require.False(mock.t, mock.gotListCalled, fnName()+" already called once before")
	assert.Equal(mock.t, mock.expectListSelector, got.String())
	mock.gotListCalled = true
	return mock.returnList, mock.returnListErr
}

func (mock *CertificateRequestListerNamespacedMock) Get(gotName string) (cr *cmapi.CertificateRequest, e error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.NotNil(mock.t, mock.expectGetCalled, fnName()+" not expected to be called")
	require.False(mock.t, mock.gotGetCalled, fnName()+" already called once before")
	assert.Equal(mock.t, mock.expectGetName, gotName)
	mock.gotGetCalled = true
	return nil, nil
}

func fnName() (fnName string) {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return "?"
	}

	fn := runtime.FuncForPC(pc)
	return fn.Name()
}
