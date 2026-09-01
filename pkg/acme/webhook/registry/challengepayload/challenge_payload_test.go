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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/registry/challengepayload"
)

type mockSolver struct {
}

func (s *mockSolver) Name() string                                { return "mock-solver" }
func (s *mockSolver) Present(ch *v1alpha1.ChallengeRequest) error { return nil }
func (s *mockSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error { return nil }
func (s *mockSolver) Initialize(kubeClientConfig *restclient.Config, stopCh <-chan struct{}) error {
	return nil
}

func TestCreate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action v1alpha1.ChallengeAction
	}{
		{
			name:   "create with present action",
			action: v1alpha1.ChallengeActionPresent,
		},
		{
			name:   "create with clean up action",
			action: v1alpha1.ChallengeActionCleanUp,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testRest := challengepayload.NewREST(&mockSolver{})
			ctx := context.Background()

			input := &v1alpha1.ChallengePayload{
				Request: &v1alpha1.ChallengeRequest{
					Action: tc.action,
				},
			}

			obj, err := testRest.Create(ctx, input, func(ctx context.Context, obj runtime.Object) error { return nil }, &metav1.CreateOptions{})
			require.NoError(t, err)

			challenge, ok := obj.(*v1alpha1.ChallengePayload)
			require.Truef(t, ok, "unexpected object type: %T", challenge)

			assert.Equal(t, ctx, challenge.Request.Context())
		})
	}
}
