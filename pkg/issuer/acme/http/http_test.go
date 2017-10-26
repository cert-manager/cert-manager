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
		ctx                context.Context
		domain, token, key string
		expectedErr        error
	}
	tests := []testT{
		{
			name: "should pass",
			reachabilityTest: func(context.Context, string, string, string) error {
				return nil
			},
			ctx: contextWithTimeout(time.Second * 30),
		},
		{
			name: "should timeout",
			reachabilityTest: func(context.Context, string, string, string) error {
				return fmt.Errorf("failed")
			},
			expectedErr: fmt.Errorf("context deadline exceeded"),
			ctx:         contextWithTimeout(time.Second * 30),
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

			err := s.Wait(test.ctx, nil, test.domain, test.token, test.key)
			if err != nil && test.expectedErr == nil {
				t.Errorf("Expected Wait to return non-nil error, but got %v", err)
				return
			}
			if err != nil && test.expectedErr != nil {
				if err.Error() != test.expectedErr.Error() {
					t.Errorf("Expected error %v from Wait, but got: %v", test.expectedErr, err)
					return
				}
			}
			if err == nil && test.expectedErr != nil {
				t.Errorf("Expected error %v from Wait, but got none", test.expectedErr)
				return
			}
			if test.expectedErr == nil && calls != requiredCallsForPass {
				t.Errorf("Expected Wait to verify reachability test passes %d times, but only checked %d", requiredCallsForPass, calls)
				return
			}
		})
	}
}
