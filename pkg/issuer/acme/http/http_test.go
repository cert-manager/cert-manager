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

package http

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// countReachabilityTestCalls is a wrapper function that allows us to count the number
// of calls to a reachabilityTest.
func countReachabilityTestCalls(counter *int, t reachabilityTest) reachabilityTest {
	return func(ctx context.Context, url *url.URL, key string) error {
		*counter++
		return t(ctx, url, key)
	}
}

func TestCheck(t *testing.T) {
	type testT struct {
		name             string
		reachabilityTest reachabilityTest
		challenge        *cmacme.Challenge
		expectedErr      bool
	}
	tests := []testT{
		{
			name: "should pass",
			reachabilityTest: func(context.Context, *url.URL, string) error {
				return nil
			},
			expectedErr: false,
		},
		{
			name: "should error",
			reachabilityTest: func(context.Context, *url.URL, string) error {
				return fmt.Errorf("failed")
			},
			expectedErr: true,
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			requiredCallsForPass := 2
			if test.challenge == nil {
				test.challenge = &cmacme.Challenge{}
			}
			s := Solver{
				testReachability: countReachabilityTestCalls(&calls, test.reachabilityTest),
				requiredPasses:   requiredCallsForPass,
			}

			err := s.Check(context.Background(), nil, test.challenge)
			if err != nil && !test.expectedErr {
				t.Errorf("Expected Check to return non-nil error, but got %v", err)
				return
			}
			if err == nil && test.expectedErr {
				t.Errorf("Expected error from Check, but got none")
				return
			}
			if !test.expectedErr && calls != requiredCallsForPass {
				t.Errorf("Expected Wait to verify reachability test passes %d times, but only checked %d", requiredCallsForPass, calls)
				return
			}
		})
	}
}
