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
	"bufio"
	"bytes"
	"runtime"
	"strings"
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

// The expectSelector is a label selector of the form:
//   "partition in (customerA, customerB),environment!=qa"
// as detailed in
// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels
func (mock *CertificateRequestListerMock) CallList(expectSelector string) *CertificateRequestListerMock {
	mock.t.Cleanup(assertWasCalled(mock.t, &mock.gotListCalled, "lister.List", assert.CallerInfo()))
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
	mock.t.Cleanup(assertWasCalled(mock.t, &mock.gotNamespaceCalled, "lister.CertificateRequests", assert.CallerInfo()))
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

func (mock *CertificateRequestListerNamespacedMock) CallGet(expectName string) *CertificateRequestListerNamespacedMock {
	mock.t.Cleanup(assertWasCalled(mock.t, &mock.gotGetCalled, "lister.CertificateRequest().Get", assert.CallerInfo()))
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
	assertCanBeCalled(mock.t, mock.expectNamespaceCalled, mock.gotNamespaceCalled, curFuncName(), assert.CallerInfo())
	assert.Equal(mock.t, mock.expectNamespace, gotNamespace)
	mock.gotNamespaceCalled = true
	return mock.returnNamespaceLister
}

func (mock *CertificateRequestListerMock) List(gotLabel labels.Selector) (ret []*cmapi.CertificateRequest, err error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	assertCanBeCalled(mock.t, mock.expectListCalled, mock.gotListCalled, curFuncName(), assert.CallerInfo())
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
	assertCanBeCalled(mock.t, mock.expectListCalled, mock.gotListCalled, curFuncName(), assert.CallerInfo())
	mock.gotListCalled = true
	assert.Equal(mock.t, mock.expectListSelector, got.String())
	return mock.returnList, mock.returnListErr
}

func (mock *CertificateRequestListerNamespacedMock) Get(gotName string) (cr *cmapi.CertificateRequest, e error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	assertCanBeCalled(mock.t, mock.expectGetCalled, mock.gotGetCalled, curFuncName(), assert.CallerInfo())
	mock.gotGetCalled = true
	assert.Equal(mock.t, mock.expectGetName, gotName)
	return nil, nil
}

// Returns the caller's function name with the full package import path.
func curFuncName() (fnName string) {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return "?"
	}

	return runtime.FuncForPC(pc).Name()
}

func assertCanBeCalled(t *testing.T, expectCalled, gotCalled bool, funcName string, stackFrames []string) {
	// No need to show the file:line of the caller of this function since
	// it belongs to "testing framework".
	stackFrames = stackFrames[1:]
	if !expectCalled {
		FailWithStack(t, stackFrames, funcName+" is not expected to be called but was called")
	}
	if gotCalled {
		FailWithStack(t, stackFrames, funcName+" was expected to run once but was run twice")
	}
}

// Since this func is meant to be called with t.Cleanup, the stack frame
// information about the source of the call is lost. Testify usually gives
// us a useful file:line indication of where an assertion failed, and
// t.Cleanup makes this stack trace unreadable with tons of testing.go
// layers.
//
// Until Testify fixes this, we keep track of the caller information right
// from the start with the stackFrames argument, and we use a patched
// version of assert.Fail that can be given a stack frames.
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
		FailWithStack(t, stackFrames[1:], funcName+" was expected to be called but was not called")
	}
}

// FailWithStack does the same as assert.Fail except it gives you the
// ability to give your own stack frames.
func FailWithStack(t *testing.T, stackFrames []string, msg string) {
	// The following is a vendored version of Testify's assert.Fail.
	type labeledContent struct{ Label, Content string }
	content := []labeledContent{
		{Label: "Error Trace", Content: strings.Join(stackFrames, "\n")},
		{Label: "Error", Content: msg},
		{Label: "Test", Content: t.Name()},
	}

	// Helper that re-wrap and indent the "content" fields of the above
	// content array.
	indentMessageLines := func(message string, longestLabelLen int) string {
		buf := new(bytes.Buffer)
		for i, scanner := 0, bufio.NewScanner(strings.NewReader(message)); scanner.Scan(); i++ {
			if i != 0 {
				buf.WriteString("\n\t" + strings.Repeat(" ", longestLabelLen+1) + "\t")
			}
			buf.WriteString(scanner.Text())
		}
		return buf.String()
	}

	longestLabelLen := 0
	for _, v := range content {
		if len(v.Label) > longestLabelLen {
			longestLabelLen = len(v.Label)
		}
	}

	// Turn the above content slice into a nicely formatted string that
	// wraps and properly indented.
	var output string
	for _, v := range content {
		output += "\t" + v.Label + ":" + strings.Repeat(" ", longestLabelLen-len(v.Label)) + "\t" + indentMessageLines(v.Content, longestLabelLen) + "\n"
	}

	t.Errorf("\n%s", ""+output)
}
