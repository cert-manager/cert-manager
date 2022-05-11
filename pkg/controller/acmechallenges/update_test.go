/*
Copyright 2022 The cert-manager Authors.

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

package acmechallenges

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
	featuretesting "k8s.io/component-base/featuregate/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestUpdateObjectStandard(t *testing.T) {
	runUpdateObjectTests(t)
}

func TestUpdateObjectSSA(t *testing.T) {
	t.Skip("Server Side Apply cannot be tested because PatchType is not supported by the fake versioned client")
	defer featuretesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.ServerSideApply, true)()
	runUpdateObjectTests(t)
}

func runUpdateObjectTests(t *testing.T) {
	simulatedUpdateError := errors.New("simulated-update-error")
	simulatedUpdateStatusError := errors.New("simulated-update-status-error")

	tests := []struct {
		name         string
		mods         []gen.ChallengeModifier
		notFound     bool
		apiResponse  clienttesting.ReactionFunc
		panicMessage string
		errorMessage string
	}{
		// Modifying the finalizers and any status fields results in both
		// finalizers and status being updated.
		{
			name: "success",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{"example.com/another-finalizer"}),
				gen.SetChallengePresented(true),
			},
		},
		// If the API server responds with a NOT FOUND error, the error is
		// ignored. Presumably the object has been deleted since the Sync
		// function began executing.
		{
			name: "not-found",
			mods: []gen.ChallengeModifier{
				gen.SetChallengePresented(true),
			},
			notFound: true,
		},
		// Only the Finalizers and Status fields can be updated. Updates to any
		// other fields suggests a programming error and results in a panic.
		{
			name: "panic-on-non-finalizer-non-status-modifications",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeDNSName("new-dns-name"),
			},
			panicMessage: "only the finalizers and status fields may be modified",
		},
		// If the Update API call fails, that error is returned.
		{
			name: "update-error-only",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{"example.com/another-finalizer"}),
			},
			apiResponse: func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetSubresource() == "" {
					return true, nil, simulatedUpdateError
				}
				return false, nil, nil
			},
			errorMessage: "when updating the finalizers: simulated-update-error",
		},
		// If the UpdateStatus API call fails, that error is returned.
		{
			name: "update-status-error-only",
			mods: []gen.ChallengeModifier{
				gen.SetChallengePresented(true),
			},
			apiResponse: func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetSubresource() == "status" {
					return true, nil, simulatedUpdateStatusError
				}
				return false, nil, nil
			},
			errorMessage: "when updating the status: simulated-update-status-error",
		},
		// If both Update and UpdateStatus API calls fail, both errors are returned.
		{
			name: "all-updates-fail",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{"example.com/another-finalizer"}),
				gen.SetChallengePresented(true),
			},
			apiResponse: func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetSubresource() == "" {
					return true, nil, simulatedUpdateError
				}
				if action.GetSubresource() == "status" {
					return true, nil, simulatedUpdateStatusError
				}
				return false, nil, nil
			},
			errorMessage: "[when updating the status: simulated-update-status-error, when updating the finalizers: simulated-update-error]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			old := gen.Challenge("c1")
			new := gen.ChallengeFrom(old, tt.mods...)
			objects := []runtime.Object{old}
			if tt.notFound {
				t.Log("Simulating a situation where the target object has been deleted")
				objects = nil
			}
			cl := fake.NewSimpleClientset(objects...)
			if tt.apiResponse != nil {
				t.Log("Simulating an API server 'update' error")
				cl.PrependReactor("update", "*", tt.apiResponse)
			}
			updater := newObjectUpdater(cl, "test-fieldmanager")
			if tt.panicMessage != "" {
				assert.PanicsWithValue(t, tt.panicMessage, func() { _ = updater.updateObject(ctx, old, new) },
					"updateObject should panic when changes are made to fields other than Finalizers and Status")
				return
			}
			t.Log("Executing the function")
			updateObjectErr := updater.updateObject(ctx, old, new)
			if tt.errorMessage == "" {
				assert.NoError(t, updateObjectErr)
			} else {
				assert.EqualError(t, updateObjectErr, tt.errorMessage)
			}

			if len(tt.mods) == 0 {
				assert.Empty(t, cl.Actions(), "There should not be any API interactions unless the object was modified")
			}

			if !tt.notFound {
				t.Log("Checking whether the object was updated")
				actual, err := cl.AcmeV1().Challenges(old.Namespace).Get(ctx, old.Name, metav1.GetOptions{})
				require.NoError(t, err)
				if updateObjectErr == nil {
					assert.Equal(t, new, actual, "updateObject did not return an error so the object in the API should have been updated")
				} else {
					if !errors.Is(updateObjectErr, simulatedUpdateError) {
						assert.Equal(t, new.Finalizers, actual.Finalizers, "The Update did not fail so the Finalizers  of the API object should have been updated")
					}
					if !errors.Is(updateObjectErr, simulatedUpdateStatusError) {
						assert.Equal(t, new.Status, actual.Status, "The UpdateStatus did not fail so the Status of the API object should have been updated")
					}
				}
			}
		})
	}
}
