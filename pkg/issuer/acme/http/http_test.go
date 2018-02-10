package http

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// contextWithTimeout calls context.WithTimeout, and throws away the cancel fn
func contextWithTimeout(t time.Duration) context.Context {
	c, _ := context.WithTimeout(context.Background(), t)
	return c
}

// countReachabilityTestCalls is a wrapper function that allows us to count the number
// of calls to a reachabilityTest.
func countReachabilityTestCalls(counter *int, t reachabilityTest) reachabilityTest {
	return func(ctx context.Context, domain, path, key string) error {
		*counter++
		return t(ctx, domain, path, key)
	}
}

func TestWait(t *testing.T) {
	type testT struct {
		name               string
		reachabilityTest   func(ctx context.Context, domain, path, key string) error
		domain, token, key string
		expectedErr        bool
	}
	tests := []testT{
		{
			name: "should pass",
			reachabilityTest: func(context.Context, string, string, string) error {
				return nil
			},
		},
		{
			name: "should fail",
			reachabilityTest: func(context.Context, string, string, string) error {
				return fmt.Errorf("failed")
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

			err := s.Check(test.domain, test.token, test.key)
			if err != nil && !test.expectedErr {
				t.Errorf("Expected Check to return non-nil error, but got %v", err)
				return
			}
			if err == nil && test.expectedErr {
				t.Errorf("Expected error from Check, but got none")
				return
			}
			if test.expectedErr == false && calls != requiredCallsForPass {
				t.Errorf("Expected Wait to verify reachability test passes %d times, but only checked %d", requiredCallsForPass, calls)
				return
			}
		})
	}
}
