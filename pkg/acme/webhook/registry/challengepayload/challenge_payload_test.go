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

package challengepayload_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apicorev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/registry/challengepayload"
)

type mockSolver struct {
	presentCalls  int
	cleanUpCalls  int
	returnedError error
	receivedCtx   context.Context
}

func (s *mockSolver) Name() string { return "mock-solver" }
func (s *mockSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	s.receivedCtx = ch.Context()
	s.presentCalls++
	return s.returnedError
}
func (s *mockSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	s.receivedCtx = ch.Context()
	s.cleanUpCalls++
	return s.returnedError
}
func (s *mockSolver) Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) error {
	return nil
}

func TestCreate(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		input                runtime.Object
		solverError          error
		expectError          bool
		expectedErrorMsg     string
		expectedPresentCalls int
		expectedCleanUpCalls int
	}{
		{
			name:                 "wrong obj type returns error",
			input:                &apicorev1.Pod{},
			expectError:          true,
			expectedErrorMsg:     "resource is not of type ChallengePayload",
			expectedPresentCalls: 0,
			expectedCleanUpCalls: 0,
		},
		{
			name:                 "nil request returns error",
			input:                &v1alpha1.ChallengePayload{},
			expectError:          true,
			expectedErrorMsg:     "payload request field cannot be empty",
			expectedPresentCalls: 0,
			expectedCleanUpCalls: 0,
		},
		{
			name: "unknown action type returns error",
			input: &v1alpha1.ChallengePayload{
				Request: &v1alpha1.ChallengeRequest{
					Action: v1alpha1.ChallengeAction("fly"),
				},
			},
			expectError:          true,
			expectedErrorMsg:     "unknown action type \"fly\"",
			expectedPresentCalls: 0,
			expectedCleanUpCalls: 0,
		},
		{
			name: "present action with solver error",
			input: &v1alpha1.ChallengePayload{
				Request: &v1alpha1.ChallengeRequest{
					UID:    "some-uid",
					Action: v1alpha1.ChallengeActionPresent,
				},
			},
			solverError:          errors.New("failed to present"),
			expectError:          false,
			expectedPresentCalls: 1,
			expectedCleanUpCalls: 0,
		},
		{
			name: "present action with solver success",
			input: &v1alpha1.ChallengePayload{
				Request: &v1alpha1.ChallengeRequest{
					UID:    "some-uid",
					Action: v1alpha1.ChallengeActionPresent,
				},
			},
			expectError:          false,
			expectedPresentCalls: 1,
			expectedCleanUpCalls: 0,
		},
		{
			name: "cleanUp action with solver error",
			input: &v1alpha1.ChallengePayload{
				Request: &v1alpha1.ChallengeRequest{
					UID:    "some-uid",
					Action: v1alpha1.ChallengeActionCleanUp,
				},
			},
			solverError:          errors.New("failed to cleanup"),
			expectError:          false,
			expectedPresentCalls: 0,
			expectedCleanUpCalls: 1,
		},
		{
			name: "cleanUp action with solver success",
			input: &v1alpha1.ChallengePayload{
				Request: &v1alpha1.ChallengeRequest{
					UID:    "some-uid",
					Action: v1alpha1.ChallengeActionCleanUp,
				},
			},
			expectError:          false,
			expectedPresentCalls: 0,
			expectedCleanUpCalls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			solver := &mockSolver{returnedError: tc.solverError}
			testRest := challengepayload.NewREST(solver)
			type ctxKey struct{}
			const sentinel = "sentinel"
			ctx := context.WithValue(t.Context(), ctxKey{}, sentinel)

			obj, err := testRest.Create(ctx, tc.input, func(ctx context.Context, obj runtime.Object) error { return nil }, &metav1.CreateOptions{})
			if tc.expectError {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.expectedErrorMsg)
			} else {
				challenge, ok := obj.(*v1alpha1.ChallengePayload)
				require.Truef(t, ok, "unexpected object type: %T", challenge)

				require.NotNil(t, challenge.Response)
				assert.Equal(t, challenge.Response.UID, challenge.Request.UID)

				if tc.solverError != nil {
					require.NotNil(t, challenge.Response.Result)
					assert.Equal(t, challenge.Response.Result.Status, "Failed")
					assert.Equal(t, challenge.Response.Result.Message, tc.solverError.Error())
					assert.False(t, challenge.Response.Success)
				} else {
					assert.True(t, challenge.Response.Success)
				}

				assert.Equal(t, sentinel, solver.receivedCtx.Value(ctxKey{}))
			}
			assert.Equal(t, tc.expectedPresentCalls, solver.presentCalls)
			assert.Equal(t, tc.expectedCleanUpCalls, solver.cleanUpCalls)
		})
	}
}
