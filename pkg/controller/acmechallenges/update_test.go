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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clienttesting "k8s.io/client-go/testing"
	featuretesting "k8s.io/component-base/featuregate/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestUpdateStatusStandard(t *testing.T) {
	featuretesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.ServerSideApply, false)
	runUpdateStatusTests(t, "update")
}

func TestUpdateStatusApply(t *testing.T) {
	featuretesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, feature.ServerSideApply, true)
	runUpdateStatusTests(t, "patch")
}

func runUpdateStatusTests(t *testing.T, verb string) {
	simulatedUpdateStatusError := errors.New("simulated-update-status-error")

	tests := []struct {
		name              string
		mods              []gen.ChallengeModifier
		notFound          bool
		updateStatusError error
		errorMessage      string
	}{
		// Modifying any status fields results in status being updated.
		{
			name: "success",
			mods: []gen.ChallengeModifier{
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
		// If the UpdateStatus API call fails, that error is returned.
		{
			name: "update-status-error",
			mods: []gen.ChallengeModifier{
				gen.SetChallengePresented(true),
			},
			updateStatusError: simulatedUpdateStatusError,
			errorMessage:      simulatedUpdateStatusError.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldChallenge := gen.Challenge("c1")
			newChallenge := gen.ChallengeFrom(oldChallenge, tt.mods...)
			cl := fake.NewClientset(oldChallenge)
			if tt.notFound {
				cl.PrependReactor(verb, "challenges/status", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Log("Simulating a situation where the target object has been deleted")
					return true, nil, apierrors.NewNotFound(schema.GroupResource{}, "")
				})
			} else if tt.updateStatusError != nil {
				cl.PrependReactor(verb, "challenges/status", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Log("Simulating a challenge/status update error")
					return true, nil, tt.updateStatusError
				})
			}

			updater := newObjectUpdater(cl, "test-fieldmanager")
			t.Log("Calling updateStatus")
			updateStatusErr := updater.updateStatus(t.Context(), oldChallenge, newChallenge)
			if tt.errorMessage == "" {
				assert.NoError(t, updateStatusErr)
			} else {
				assert.EqualError(t, updateStatusErr, tt.errorMessage)
			}

			if len(tt.mods) == 0 {
				assert.Empty(t, cl.Actions(), "There should not be any API interactions unless the object was modified")
			}

			if !tt.notFound {
				t.Log("Checking whether the object was updated")
				actual, err := cl.AcmeV1().Challenges(oldChallenge.Namespace).Get(t.Context(), oldChallenge.Name, metav1.GetOptions{})
				require.NoError(t, err)
				if updateStatusErr == nil {
					expected := newChallenge
					expected.APIVersion = actual.APIVersion
					expected.Kind = actual.Kind
					// We ignore differences in .ManagedFields since the expected object does not have them.
					// FIXME: don't ignore this field
					expected.ManagedFields = actual.ManagedFields
					assert.Equal(t, expected, actual, "updateStatus did not return an error so the object in the API should have been updated")
				} else if !errors.Is(updateStatusErr, simulatedUpdateStatusError) {
					assert.Equal(t, newChallenge.Status, actual.Status, "The updateStatus did not fail so the Status of the API object should have been updated")
				}
			}
		})
	}
}

func TestApplyFinalizers(t *testing.T) {
	simulatedApplyError := errors.New("simulated-apply-error")

	tests := []struct {
		name         string
		mods         []gen.ChallengeModifier
		finalizers   []string
		notFound     bool
		applyError   error
		errorMessage string
	}{
		// Modifying the finalizers results in finalizers being updated.
		{
			name:       "success",
			finalizers: []string{"example.com/another-finalizer"},
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{"example.com/another-finalizer"}),
			},
		},
		// If the API server responds with a NOT FOUND error, the error is
		// ignored. Presumably the object has been deleted since the Sync
		// function began executing.
		{
			name:       "not-found",
			finalizers: []string{"example.com/another-finalizer"},
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{"example.com/another-finalizer"}),
			},
			notFound: true,
		},
		// If the Apply API call fails, that error is returned.
		{
			name:       "apply-error",
			finalizers: []string{"example.com/another-finalizer"},
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{"example.com/another-finalizer"}),
			},
			applyError:   simulatedApplyError,
			errorMessage: simulatedApplyError.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := gen.Challenge("c1")
			cl := fake.NewClientset(challenge)
			if tt.notFound {
				cl.PrependReactor("patch", "challenges", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Log("Simulating a situation where the target object has been deleted")
					return true, nil, apierrors.NewNotFound(schema.GroupResource{}, "")
				})
			} else if tt.applyError != nil {
				cl.PrependReactor("patch", "challenges", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Log("Simulating a challenge update error")
					return true, nil, tt.applyError
				})
			}
			updater := newObjectUpdater(cl, "test-fieldmanager")
			t.Log("Calling applyFinalizers")
			applyFinalizersErr := updater.applyFinalizers(t.Context(), challenge, tt.finalizers)
			if tt.errorMessage == "" {
				assert.NoError(t, applyFinalizersErr)
			} else {
				assert.EqualError(t, applyFinalizersErr, tt.errorMessage)
			}

			if len(tt.mods) == 0 {
				assert.Empty(t, cl.Actions(), "There should not be any API interactions unless the object was modified")
			}

			if !tt.notFound {
				t.Log("Checking whether the object was updated")
				actual, err := cl.AcmeV1().Challenges(challenge.Namespace).Get(t.Context(), challenge.Name, metav1.GetOptions{})
				require.NoError(t, err)
				if applyFinalizersErr == nil {
					expected := gen.ChallengeFrom(challenge, tt.mods...)
					expected.APIVersion = actual.APIVersion
					expected.Kind = actual.Kind
					// We ignore differences in .ManagedFields since the expected object does not have them.
					// FIXME: don't ignore this field
					expected.ManagedFields = actual.ManagedFields
					assert.Equal(t, expected, actual, "applyFinalizers did not return an error so the object in the API should have been updated")
				} else if !errors.Is(applyFinalizersErr, simulatedApplyError) {
					assert.Equal(t, tt.finalizers, actual.Finalizers, "The applyFinalizers failed with a different error so the Finalizers of the API object should have been updated")
				}
			}
		})
	}
}
