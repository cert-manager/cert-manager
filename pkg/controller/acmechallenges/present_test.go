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

package acmechallenges

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/tools/record"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_presentStep_Required(t *testing.T) {
	tests := []struct {
		name      string
		presented bool
		want      bool
	}{
		{
			name:      "not-required-if-presented",
			presented: true,
			want:      false,
		},
		{
			name:      "required-if-not-presented",
			presented: false,
			want:      true,
		},
	}
	for _, tt := range tests {
		ch := gen.Challenge("example", gen.SetChallengePresented(tt.presented))
		t.Run(tt.name, func(t *testing.T) {
			o := &presentStep{
				ch: ch,
			}
			assert.Equal(t, tt.want, o.Required())
		})
	}
}

func Test_presentStep_Run(t *testing.T) {
	simulatedError := errors.New("simulated error")
	tests := []struct {
		name               string
		solverPresentError error
		wantErr            error
	}{
		{
			name:               "present-succeeds",
			solverPresentError: nil,
			wantErr:            nil,
		},
		{
			name:               "present-fails",
			solverPresentError: simulatedError,
			wantErr:            simulatedError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedChallenge := gen.Challenge("example",
				gen.SetChallengePresented(false),
				gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
				gen.SetChallengeReason("existing-reason-which-should-be-overwritten"))
			suppliedChallenge := expectedChallenge.DeepCopy()

			expectedIssuer := gen.Issuer("example")
			suppliedIssuer := expectedIssuer.DeepCopy()
			recorder := record.NewFakeRecorder(1)

			o := &presentStep{
				ch: suppliedChallenge,
				solver: &fakeSolver{
					fakePresent: func(ctx context.Context, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) error {
						assert.Equal(t, expectedIssuer, issuer,
							"the issuer assigned to the step should be supplied to solver.Present unmodified")
						assert.Equal(t, expectedChallenge, ch,
							"the challenge assigned to the step should be supplied to solver.Present unmodified")
						return tt.solverPresentError
					},
				},
				issuer:   suppliedIssuer,
				recorder: recorder,
			}
			actualErr := o.Run(context.TODO())
			assert.Equal(t, tt.wantErr, actualErr, "unexpected error")
			assert.Equal(t, expectedIssuer, suppliedIssuer, "the issuer assigned to the step should not be modified")
			assert.Equal(
				t,
				gen.ChallengeFrom(expectedChallenge,
					gen.SetChallengePresented(true),
					gen.SetChallengeReason("")),
				gen.ChallengeFrom(suppliedChallenge,
					gen.SetChallengePresented(true),
					gen.SetChallengeReason("")),
				"only Status.Presented and Status.Reason should be modified",
			)
			actualEvent := <-recorder.Events
			assert.Empty(t, recorder.Events, "only one event should be recorded")
			if tt.solverPresentError == nil {
				assert.True(t, suppliedChallenge.Status.Presented,
					"status.presented should be true if solver.Present succeeds")
				assert.Empty(t, suppliedChallenge.Status.Reason,
					"status.reason should be empty if solver.Present succeeds")
				assert.Equal(t, "Normal Presented Presented challenge using HTTP-01 challenge mechanism", actualEvent,
					"A Normal event should be recorded if solver.Present succeeds")
			} else {
				assert.False(t, suppliedChallenge.Status.Presented,
					"status.presented should be false if solver.Present fails")
				assert.Equal(t, actualErr.Error(), suppliedChallenge.Status.Reason,
					"status.reason should be the error message returned by  solver.Present if it fails")
				assert.Equal(t, fmt.Sprintf("Warning PresentError Error presenting challenge: %s", tt.solverPresentError), actualEvent,
					"A Warning event should be recorded if solver.Present fails")
			}
		})
	}
}
