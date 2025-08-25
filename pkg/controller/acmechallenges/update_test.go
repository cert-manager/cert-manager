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
	"errors"
	"fmt"
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
	runUpdateObjectTests(t, "update")
}

func TestUpdateObjectSSA(t *testing.T) {
	featuretesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.ServerSideApply, true)
	runUpdateObjectTests(t, "patch")
}

func runUpdateObjectTests(t *testing.T, verb string) {
	simulatedUpdateError := errors.New("simulated-update-error")
	simulatedUpdateStatusError := errors.New("simulated-update-status-error")

	// NOTE: We cannot test updates to both the main resource and status
	// subresource in the same test using APPLY as the fake.NewClientset used
	// in these tests uses a very simple object tracker that does not track main and
	// subresource fields separately, which is required for SSA to function.
	// For reference see these comments in upstream K8s code:
	// - https://github.com/kubernetes/kubernetes/blob/790393ae92e97262827d4f1fba24e8ae65bbada0/staging/src/k8s.io/client-go/testing/fixture.go#L97-L99
	// - https://github.com/kubernetes/kubernetes/blob/790393ae92e97262827d4f1fba24e8ae65bbada0/staging/src/k8s.io/client-go/testing/fixture.go#L167-L169
	// The fake client works for UPDATE, but since the K8s ecosystem is moving towards SSA,
	// we should try to improve our code (and/or test strategy) long-term.
	tests := []struct {
		name              string
		skip              bool
		mods              []gen.ChallengeModifier
		notFound          bool
		updateError       error
		updateStatusError error
		errorMessage      string
	}{
		// Modifying the finalizers and any status fields results in both
		// finalizers and status being updated.
		{
			name: "success",
			// FIXME: Skip test case when using SSA. See description above.
			skip: verb == "patch",
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
		// other fields suggests a programming error an argument error.
		{
			name: "error-on-non-finalizer-non-status-modifications",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeDNSName("new-dns-name"),
			},
			errorMessage: fmt.Sprintf(
				"%s: in updateObject: unexpected differences between old and new: only the finalizers and status fields may be modified",
				argumentError,
			),
		},
		// If the Update API call fails, that error is returned.
		{
			name: "update-error-only",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{"example.com/another-finalizer"}),
			},
			updateError:  simulatedUpdateError,
			errorMessage: fmt.Sprintf("when updating the finalizers: %s", simulatedUpdateError),
		},
		// If the UpdateStatus API call fails, that error is returned.
		{
			name: "update-status-error-only",
			mods: []gen.ChallengeModifier{
				gen.SetChallengePresented(true),
			},
			updateStatusError: simulatedUpdateStatusError,
			errorMessage:      fmt.Sprintf("when updating the status: %s", simulatedUpdateStatusError),
		},
		// If both Update and UpdateStatus API calls fail, both errors are returned.
		{
			name: "all-updates-fail",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{"example.com/another-finalizer"}),
				gen.SetChallengePresented(true),
			},
			updateError:       simulatedUpdateError,
			updateStatusError: simulatedUpdateStatusError,
			errorMessage: fmt.Sprintf(
				"[when updating the status: %s, when updating the finalizers: %s]",
				simulatedUpdateStatusError,
				simulatedUpdateError,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip("The fake client doesn't support K8s subresources like status when using SSA.")
			}

			oldChallenge := gen.Challenge("c1")
			newChallenge := gen.ChallengeFrom(oldChallenge, tt.mods...)
			objects := []runtime.Object{oldChallenge}
			if tt.notFound {
				t.Log("Simulating a situation where the target object has been deleted")
				objects = nil
			}
			cl := fake.NewClientset(objects...)
			if tt.updateError != nil {
				cl.PrependReactor(verb, "challenges", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Log("Simulating a challenge update error")
					return true, nil, tt.updateError
				})
			}
			if tt.updateStatusError != nil {
				cl.PrependReactor(verb, "challenges/status", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Log("Simulating a challenge/status update error")
					return true, nil, tt.updateStatusError
				})
			}
			updater := newObjectUpdater(cl, "test-fieldmanager")
			t.Log("Calling updateObject")
			updateObjectErr := updater.updateObject(t.Context(), oldChallenge, newChallenge)
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
				actual, err := cl.AcmeV1().Challenges(oldChallenge.Namespace).Get(t.Context(), oldChallenge.Name, metav1.GetOptions{})
				require.NoError(t, err)
				if updateObjectErr == nil {
					expected := newChallenge
					expected.APIVersion = actual.APIVersion
					expected.Kind = actual.Kind
					// We ignore differences in .ManagedFields since the expected object does not have them.
					// FIXME: don't ignore this field
					expected.ManagedFields = actual.ManagedFields
					assert.Equal(t, expected, actual, "updateObject did not return an error so the object in the API should have been updated")
				} else {
					if !errors.Is(updateObjectErr, simulatedUpdateError) {
						assert.Equal(t, newChallenge.Finalizers, actual.Finalizers, "The Update did not fail so the Finalizers  of the API object should have been updated")
					}
					if !errors.Is(updateObjectErr, simulatedUpdateStatusError) {
						assert.Equal(t, newChallenge.Status, actual.Status, "The UpdateStatus did not fail so the Status of the API object should have been updated")
					}
				}
			}
		})
	}
}
