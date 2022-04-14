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

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_finalizerRequired(t *testing.T) {
	tests := []struct {
		name       string
		finalizers []string
		want       bool
	}{
		{
			name:       "no-finalizers",
			finalizers: nil,
			want:       true,
		},
		{
			name:       "only-native-finalizer",
			finalizers: []string{cmacme.ACMEFinalizer},
			want:       false,
		},
		{
			name:       "some-foreign-finalizers",
			finalizers: []string{"f1", "f2", cmacme.ACMEFinalizer, "f3"},
			want:       false,
		},
		{
			name:       "only-foreign-finalizers",
			finalizers: []string{"f1", "f2", "f3"},
			want:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(
				t,
				tt.want,
				finalizerRequired(
					gen.Challenge("example", gen.SetChallengeFinalizers(tt.finalizers)),
				),
			)
		})
	}
}

type fakeChallengeUpdater struct {
	fakeUpdateOrApply func(context.Context, *cmacme.Challenge) (*cmacme.Challenge, error)
}

func (o *fakeChallengeUpdater) updateOrApply(ctx context.Context, ch *cmacme.Challenge) (*cmacme.Challenge, error) {
	return o.fakeUpdateOrApply(ctx, ch)
}

func Test_addFinalizer(t *testing.T) {
	simulatedError := errors.New("simulated-error")
	tests := []struct {
		name      string
		updateErr error
		wantErr   error
	}{
		{
			name:      "update-success",
			updateErr: nil,
			wantErr:   nil,
		},
		{
			name:      "update-failure",
			updateErr: simulatedError,
			wantErr:   simulatedError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := gen.Challenge("example")
			originalCh := ch.DeepCopy()
			newCh, err := addFinalizer(
				&fakeChallengeUpdater{
					fakeUpdateOrApply: func(_ context.Context, ch *cmacme.Challenge) (*cmacme.Challenge, error) {
						if tt.updateErr != nil {
							return nil, tt.updateErr
						}
						ch = ch.DeepCopy()
						// Update the generation to simulate the sort of change
						// that the API server will return.
						ch.Generation += 1
						return ch, nil
					},
				},
				context.TODO(),
				ch,
			)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, originalCh, ch, "the supplied challenge should never be modified")
			if err == nil {
				assert.EqualValues(t, 1, newCh.Generation-originalCh.Generation,
					"if the update succeeds the supplied challenge pointer should be updated with the updated challenge")
			} else {
				assert.Nil(t, newCh, "if the update fails the returned challenge should be nil")
			}
		})
	}
}
