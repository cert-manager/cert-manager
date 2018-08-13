/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package http

import (
	"context"
	"fmt"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

// countReachabilityTestCalls is a wrapper function that allows us to count the number
// of calls to a reachabilityTest.
func countReachabilityTestCalls(counter *int, t reachabilityTest) reachabilityTest {
	return func(ctx context.Context, domain, path, key string) (bool, error) {
		*counter++
		return t(ctx, domain, path, key)
	}
}

func TestCheck(t *testing.T) {
	type testT struct {
		name             string
		reachabilityTest reachabilityTest
		challenge        v1alpha1.ACMEOrderChallenge
		expectedErr      bool
		expectedOk       bool
	}
	tests := []testT{
		{
			name: "should pass",
			reachabilityTest: func(context.Context, string, string, string) (bool, error) {
				return true, nil
			},
			expectedOk: true,
		},
		{
			name: "should fail",
			reachabilityTest: func(context.Context, string, string, string) (bool, error) {
				return false, nil
			},
		},
		{
			name: "should error",
			reachabilityTest: func(context.Context, string, string, string) (bool, error) {
				return false, fmt.Errorf("failed")
			},
			expectedErr: true,
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			requiredCallsForPass := 5
			s := Solver{
				testReachability: countReachabilityTestCalls(&calls, test.reachabilityTest),
				requiredPasses:   requiredCallsForPass,
			}

			ok, err := s.Check(test.challenge)
			if err != nil && !test.expectedErr {
				t.Errorf("Expected Check to return non-nil error, but got %v", err)
				return
			}
			if err == nil && test.expectedErr {
				t.Errorf("Expected error from Check, but got none")
				return
			}
			if test.expectedOk != ok {
				t.Errorf("Expected ok=%t but got ok=%t", test.expectedOk, ok)
			}
			if test.expectedOk && calls != requiredCallsForPass {
				t.Errorf("Expected Wait to verify reachability test passes %d times, but only checked %d", requiredCallsForPass, calls)
				return
			}
		})
	}
}
