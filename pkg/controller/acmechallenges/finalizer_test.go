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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestAddCleanupFinalizer(t *testing.T) {
	tests := []struct {
		name       string
		finalizers []string
		want       bool
	}{
		// Add the finalizer if empty
		{
			name:       "no-finalizers",
			finalizers: []string{},
			want:       true,
		},
		// Noop if the finalizer is the only one
		{
			name:       "only-native-finalizer",
			finalizers: []string{cmacme.ACMEFinalizer},
			want:       false,
		},
		// Noop if the finalizer is one of many
		{
			name:       "some-foreign-finalizers",
			finalizers: []string{"f1", "f2", cmacme.ACMEFinalizer, "f3"},
			want:       false,
		},
		// Add the finalizer if there are only other finalizers
		{
			name:       "only-foreign-finalizers",
			finalizers: []string{"f1", "f2", "f3"},
			want:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := gen.Challenge("example", gen.SetChallengeFinalizers(tt.finalizers))
			chOriginal := ch.DeepCopy()
			added := addCleanupFinalizer(ch)

			assert.Equal(t, tt.want, added)
			if added {
				assert.Equal(t, cmacme.ACMEFinalizer, ch.Finalizers[len(ch.Finalizers)-1], "The finalizer should be added at the end")
				assert.Equal(t, chOriginal.Finalizers, ch.Finalizers[:len(ch.Finalizers)-1], "The original finalizers should not be changed or re-ordered")
			} else {
				assert.Equal(t, chOriginal.Finalizers, ch.Finalizers, "The finalizers should not be changed if the desired finalizer is already present")
			}
			assert.Equal(
				t,
				gen.ChallengeFrom(chOriginal, gen.SetChallengeFinalizers(nil)),
				gen.ChallengeFrom(ch, gen.SetChallengeFinalizers(nil)),
				"Only the finalizers field should ever change",
			)
		})
	}
}

func TestChallengeFinished(t *testing.T) {
	tests := []struct {
		name      string
		challenge *cmacme.Challenge
		result    bool
	}{
		// If challenge is deleted attempt to cleanup
		{
			name: "deleted",
			challenge: gen.Challenge("c1",
				gen.SetChallengeDeletionTimestamp(metav1.Now()),
			),
			result: true,
		},
		// If challenge is in a finished state, attempt to cleanup
		{
			name: "final-state",
			challenge: gen.Challenge("c1",
				gen.SetChallengeState(cmacme.Invalid),
			),
			result: true,
		},
		// If challenge is deleted and in a finished state, attempt to cleanup
		{
			name: "deleted-and-final-state",
			challenge: gen.Challenge("c1",
				gen.SetChallengeDeletionTimestamp(metav1.Now()),
				gen.SetChallengeState(cmacme.Invalid),
			),
			result: true,
		},
		// If the challenge is neither deleted nor finished, skip the cleanup
		{
			name:      "not-finished",
			challenge: gen.Challenge("c1"),
			result:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.result, challengeFinished(tt.challenge))
		})
	}
}

func TestHandleCleanup(t *testing.T) {
	simulatedCleanupError := errors.New("simulated-cleanup-error")
	tests := []struct {
		name         string
		mods         []gen.ChallengeModifier
		cleanupError error
		errorMessage string
	}{
		// Invoke solver.Cleanup if the finalizer is present and remove the
		// finalizer and reset the status fields if it succeeds
		{
			name: "success-with-cleanup",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{cmacme.ACMEFinalizer}),
			},
		},
		// Skip the solver.Cleanup when the finalizer absent, but reset the
		// status fields if it succeeds
		{
			name:         "success-skip-cleanup",
			cleanupError: simulatedCleanupError,
		},
		// Return the solver.Cleanup error if it fails and do not remove the
		// finalizer nor update he status fields.
		{
			name: "cleanup-error",
			mods: []gen.ChallengeModifier{
				gen.SetChallengeFinalizers([]string{cmacme.ACMEFinalizer}),
			},
			cleanupError: simulatedCleanupError,
			errorMessage: "Error cleaning up challenge: simulated-cleanup-error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			solver := &fakeSolver{
				fakeCleanUp: func(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
					return tt.cleanupError
				},
			}
			issuer := gen.Issuer("issuer1")
			ch := gen.Challenge("challenge1", append(tt.mods, gen.SetChallengeProcessing(true), gen.SetChallengePresented(true))...)
			chOriginal := ch.DeepCopy()
			err := handleCleanup(ctx, solver, issuer, ch)
			if tt.errorMessage == "" {
				assert.NoError(t, err)
				assert.NotContains(t, ch.Finalizers, cmacme.ACMEFinalizer, "The finalizer should be removed if cleanup succeeded")
				assert.False(t, ch.Status.Processing)
				assert.False(t, ch.Status.Presented)
			} else {
				assert.EqualError(t, err, tt.errorMessage)
				assert.Equal(t, chOriginal, ch, "The challenge should be unchanged if the cleanup failed")
				assert.True(t, ch.Status.Processing)
				assert.True(t, ch.Status.Presented)
			}
		})
	}
}
