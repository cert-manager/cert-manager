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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func TestSetDefaultsACMEChallengeSolver(t *testing.T) {
	type testCase struct {
		in  *v1.ACMEChallengeSolver
		out *v1.ACMEChallengeSolver
	}
	tests := map[string]testCase{
		"strategy not set": {
			in: &v1.ACMEChallengeSolver{},
			out: &v1.ACMEChallengeSolver{
				ReadinessStrategy: &v1.ChallengeReadinessStrategy{
					SelfCheck: &v1.ChallengeSelfCheckReadinessStrategy{},
				},
				ReadinessGates: []v1.ChallengeReadinessGate{
					{
						ConditionType: v1.ChallengConditionSelfCheckSucceeded,
					},
				},
			},
		},
		"SelfCheck strategy set": {
			in: &v1.ACMEChallengeSolver{
				ReadinessStrategy: &v1.ChallengeReadinessStrategy{
					SelfCheck: &v1.ChallengeSelfCheckReadinessStrategy{},
				},
			},
			out: &v1.ACMEChallengeSolver{
				ReadinessStrategy: &v1.ChallengeReadinessStrategy{
					SelfCheck: &v1.ChallengeSelfCheckReadinessStrategy{},
				},
				ReadinessGates: []v1.ChallengeReadinessGate{
					{
						ConditionType: v1.ChallengConditionSelfCheckSucceeded,
					},
				},
			},
		},
		"DelayedAccept strategy set without timeout": {
			in: &v1.ACMEChallengeSolver{
				ReadinessStrategy: &v1.ChallengeReadinessStrategy{
					DelayedAccept: &v1.ChallengeDelayedAcceptReadinessStrategy{},
				},
			},
			out: &v1.ACMEChallengeSolver{
				ReadinessStrategy: &v1.ChallengeReadinessStrategy{
					DelayedAccept: &v1.ChallengeDelayedAcceptReadinessStrategy{
						Timeout: metav1.Duration{Duration: defaultDelayedAcceptTimeout},
					},
				},
				ReadinessGates: []v1.ChallengeReadinessGate{
					{
						ConditionType: v1.ChallengConditionDelayedAcceptTimeoutReached,
					},
				},
			},
		},
		"DelayedAccept strategy set with timeout": {
			in: &v1.ACMEChallengeSolver{
				ReadinessStrategy: &v1.ChallengeReadinessStrategy{
					DelayedAccept: &v1.ChallengeDelayedAcceptReadinessStrategy{
						Timeout: metav1.Duration{Duration: time.Minute * 9},
					},
				},
			},
			out: &v1.ACMEChallengeSolver{
				ReadinessStrategy: &v1.ChallengeReadinessStrategy{
					DelayedAccept: &v1.ChallengeDelayedAcceptReadinessStrategy{
						Timeout: metav1.Duration{Duration: time.Minute * 9},
					},
				},
				ReadinessGates: []v1.ChallengeReadinessGate{
					{
						ConditionType: v1.ChallengConditionDelayedAcceptTimeoutReached,
					},
				},
			},
		},
	}

	for description, tc := range tests {
		tc := tc
		t.Run(description, func(t *testing.T) {
			in := tc.in.DeepCopy()
			setDefaults_ACMEChallengeSolver(in)
			require.Equal(t, tc.out, in)
		})
	}
}
