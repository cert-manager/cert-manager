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

// MockCertificateRequestLister allows you to create a mock lister. This
// mock lister will make sure that the input parameters that the mock
// functions will be called with match the expected input parameters that
// you specified e.g., with CallList. The mock also makes sure the
// function(s) expected are actually called (or not called, depending).
//
// For example:
//
//   mock := MockCertificateRequestLister(t)
//   mock.
//       CallCertificateRequest("default").
//       CallGet("certificate-1").
//       ReturnGet(&cmapi.CertificateRequest{}, nil)
//
// will create a lister mock that expects the following call excatly once:
//
//   lister.CertificateRequest("default").Get("certificate-1")
//
// If you want to specify that no call should be made altogether, just give
// it the mock lister without any calls specified:
//
//   mock := MockCertificateRequestLister(t)
//
// Note that this mock lister is only able to account for either one or
// zero call to the Get and List functions, which is fine in our tests.
func MockCertificateRequestLister(t *testing.T) *CertificateRequestListerMock {
	return &CertificateRequestListerMock{t: t}
}

// The expectSelector is a label selector of the form:
//   "partition in (customerA, customerB),environment!=qa"
// as detailed in
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
func (mock *CertificateRequestListerMock) CallList(expectSelector string) *CertificateRequestListerMock {
	mock.t.Cleanup(func() {
		assert.True(mock.t, mock.gotListCalled, "lister.List was expected to be called but was not called")
	})
	mock.expectListCalled = true
	mock.expectListSelector = expectSelector
	return mock
}

func (mock *CertificateRequestListerMock) ReturnList(returnList []*cmapi.CertificateRequest, returnErr error) *CertificateRequestListerMock {
	mock.returnList = returnList
	mock.returnListErr = returnErr
	return mock
}

// This mock function does not have a matching ReturnCertificateRequests
// mock func. The return values of this mock function are already taken
// care of.
func (mock *CertificateRequestListerMock) CallCertificateRequests(expectNamespace string) *CertificateRequestListerNamespacedMock {
	mock.t.Cleanup(func() {
		assert.True(mock.t, mock.gotNamespaceCalled, "lister.CertificateRequests was expected to be called but was not called")
	})
	mock.expectNamespaceCalled = true
	mock.expectNamespace = expectNamespace
	mock.returnNamespaceLister = &CertificateRequestListerNamespacedMock{t: mock.t}
	return mock.returnNamespaceLister
}

// The expectSelector is a label selector of the form:
//   "partition in (customerA, customerB),environment!=qa"
// as detailed in
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
func (mock *CertificateRequestListerNamespacedMock) CallList(expectSelector string) *CertificateRequestListerNamespacedMock {
	mock.t.Cleanup(func() {
		assert.True(mock.t, mock.gotListCalled, "lister.CertificateRequest().List was expected to be called but was not called")
	})
	mock.expectListCalled = true
	mock.expectListSelector = expectSelector
	return mock
}

func (mock *CertificateRequestListerNamespacedMock) ReturnList(returnList []*cmapi.CertificateRequest, returnErr error) *CertificateRequestListerNamespacedMock {
	mock.returnList = returnList
	mock.returnListErr = returnErr
	return mock
}

func (mock *CertificateRequestListerNamespacedMock) CallGet(expectName string) *CertificateRequestListerNamespacedMock {
	mock.t.Cleanup(func() {
		assert.True(mock.t, mock.gotListCalled, "lister.CertificateRequest().Get was expected to be called but was not called")
	})
	mock.expectGetCalled = true
	mock.expectGetName = expectName
	return mock
}

func (mock *CertificateRequestListerNamespacedMock) ReturnGet(returnGet *cmapi.CertificateRequest, returnErr error) *CertificateRequestListerNamespacedMock {
	mock.returnGet = returnGet
	mock.returnGetErr = returnErr
	return mock
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
	require.True(mock.t, mock.expectNamespaceCalled, curFuncName()+" not expected to be called")
	require.False(mock.t, mock.gotNamespaceCalled, curFuncName()+" already called once before")
	assert.Equal(mock.t, mock.expectNamespace, gotNamespace)
	mock.gotNamespaceCalled = true
	return mock.returnNamespaceLister
}

func (mock *CertificateRequestListerMock) List(gotLabel labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.True(mock.t, mock.expectListCalled, curFuncName()+" not expected to be called")
	require.False(mock.t, mock.gotListCalled, curFuncName()+" already called once before")
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
	require.NotNil(mock.t, mock.expectListCalled, curFuncName()+" not expected to be called")
	require.False(mock.t, mock.gotListCalled, curFuncName()+" already called once before")
	assert.Equal(mock.t, mock.expectListSelector, got.String())
	mock.gotListCalled = true
	return mock.returnList, mock.returnListErr
}

func (mock *CertificateRequestListerNamespacedMock) Get(gotName string) (cr *cmapi.CertificateRequest, e error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.NotNil(mock.t, mock.expectGetCalled, curFuncName()+" not expected to be called")
	require.False(mock.t, mock.gotGetCalled, curFuncName()+" already called once before")
	assert.Equal(mock.t, mock.expectGetName, gotName)
	mock.gotGetCalled = true
	return nil, nil
}

func curFuncName() (fnName string) {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return "?"
	}

	fn := runtime.FuncForPC(pc)
	return fn.Name()
}
