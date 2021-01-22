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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlist "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
)

// MockCertificateRequestLister allows you to create a mock certificate
// requests lister. This mock lister does three things:
//
//  1. it checks that the function under test has made the call to the mocked
//     function using the expected input arguments.
//  2. it checks that the function under test actually called the mock as
//     expected. Enforcing whether or not the call to the mock has been made
//     allows us to make sure the expected input arguments have been checked.
//  3. it returns the given "mocked" return values.
//
// For example:
//
//   mock := MockCertificateRequestLister(t)
//   mock.
//       CallCertificateRequest("default").
//       CallGet("certificate-1").
//       ReturnGet(&cmapi.CertificateRequest{}, nil)
//
// will create a lister mock that expects the following call exactly once:
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

type CertificateRequestListerMock struct {
	t  *testing.T
	mu sync.Mutex

	expectNamespaceCalled, gotNamespaceCalled bool
	expectNamespace                           string
	returnNamespaceLister                     *CertificateRequestListerNamespacedMock
}

// This mock function does not have a matching ReturnCertificateRequests
// mock func. The return values of this mock function are already taken
// care of.
func (mock *CertificateRequestListerMock) CallCertificateRequests(expectNamespace string) *CertificateRequestListerNamespacedMock {
	mock.t.Cleanup(assertWasCalled(mock.t, &mock.gotNamespaceCalled, "lister.CertificateRequests", assert.CallerInfo()))
	mock.expectNamespaceCalled = true
	mock.expectNamespace = expectNamespace
	mock.returnNamespaceLister = &CertificateRequestListerNamespacedMock{t: mock.t}
	return mock.returnNamespaceLister
}

func (mock *CertificateRequestListerMock) CallList(_ string) *CertificateRequestListerMock {
	mock.t.Error("lister.List is not implemented in the mock, please implement it :-)")
	return nil
}

func (mock *CertificateRequestListerMock) CertificateRequests(gotNamespace string) cmlist.CertificateRequestNamespaceLister {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	assertCanBeCalled(mock.t, mock.expectNamespaceCalled, mock.gotNamespaceCalled, curFuncName(), assert.CallerInfo())
	assert.Equal(mock.t, mock.expectNamespace, gotNamespace)
	mock.gotNamespaceCalled = true
	return mock.returnNamespaceLister
}

func (mock *CertificateRequestListerMock) List(gotLabel labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	mock.t.Error("lister.CertificateRequest().List is not implemented in the mock, please implement it :-)")
	return nil, nil
}

type CertificateRequestListerNamespacedMock struct {
	t  *testing.T
	mu sync.Mutex

	expectListCalled, gotListCalled bool
	expectListSelector              string
	returnList                      []*cmapi.CertificateRequest
	returnListErr                   error
}

func (mock *CertificateRequestListerNamespacedMock) List(got labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	assertCanBeCalled(mock.t, mock.expectListCalled, mock.gotListCalled, curFuncName(), assert.CallerInfo())
	mock.gotListCalled = true
	assert.Equal(mock.t, mock.expectListSelector, got.String())
	return mock.returnList, mock.returnListErr
}

// The expectSelector is a label selector of the form:
//   "partition in (customerA, customerB),environment!=qa"
// as detailed in
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
func (mock *CertificateRequestListerNamespacedMock) CallList(expectSelector string) *CertificateRequestListerNamespacedMock {
	mock.t.Cleanup(assertWasCalled(mock.t, &mock.gotListCalled, "lister.CertificateRequest().List", assert.CallerInfo()))
	mock.expectListCalled = true
	mock.expectListSelector = expectSelector
	return mock
}

func (mock *CertificateRequestListerNamespacedMock) ReturnList(returnList []*cmapi.CertificateRequest, returnErr error) *CertificateRequestListerNamespacedMock {
	mock.returnList = returnList
	mock.returnListErr = returnErr
	return mock
}

func (mock *CertificateRequestListerNamespacedMock) Get(_ string) (*cmapi.CertificateRequest, error) {
	mock.t.Error("lister.CertificateRequest().List is not implemented in the mock, please implement it :-)")
	return nil, nil
}

func (mock *CertificateRequestListerNamespacedMock) CallGet(expectName string) *CertificateRequestListerNamespacedMock {
	mock.t.Error("lister.CertificateRequest().List is not implemented in the mock, please implement it :-)")
	return nil
}

// Whenever a mocked function is called, we need to fail if this call was
// already made or if this call never should have happened.
func assertCanBeCalled(t *testing.T, expectCalled, gotCalled bool, funcName string, stackFrames []string) {
	// No need to show the file:line of the caller of this function since
	// it belongs to "testing framework".
	stackFrames = stackFrames[1:]
	if !expectCalled {
		failWithStack(t, stackFrames, funcName+" is not expected to be called but was called")
	}
	if gotCalled {
		failWithStack(t, stackFrames, funcName+" was expected to run once but was run twice")
	}
}

// This function is meant to be run with t.Cleanup. During the cleanup,
// this function checks that the function named funcName has been called as
// expected.
func assertWasCalled(t *testing.T, funcWasCalled *bool, funcName string, stackFrames []string) func() {
	return func() {
		// We pass this boolean by reference due to the fact that this
		// assertion is meant to be called in t.Cleanup, which means we
		// cannot pass by value. If we were to pass by value, we would
		// obtain the boolean at the time if the call to t.Cleanup, not the
		// boolean value that was modified throughout the test.
		if *funcWasCalled {
			// Happy case, the function that expected to be run was run.
			return
		}

		// No need to show the file:line of the caller of this function since
		// it belongs to "testing frqmework".
		failWithStack(t, stackFrames[1:], funcName+" was expected to be called but was not called")
	}
}
