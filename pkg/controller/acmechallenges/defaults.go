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
	"time"

	"k8s.io/utils/pointer"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// copyOfChallengeWithDefaultsApplied copies the supplied challenge, applies
// defaults to the copy and returns the copy.
func copyOfChallengeWithDefaultsApplied(in *v1.Challenge) *v1.Challenge {
	out := in.DeepCopy()
	setDefaults_ACMEChallengeSolver(&out.Spec.Solver)
	return out
}

// setDefaults_ACMEChallengeSolver sets default ReadinessStrategy to
// SelfCheck and if empty it populates ReadinessGates with a condition type
// corresponding to the configured ReadinessStrategy.
// If ReadinessGates is not empty it does not change it on the assumption that
// the user knows best; it is the users responsibility to add the
// SelfCheckSucceeded or DelayedAcceptTimeoutReached conditions if they want to
// use those either of those builtin ReadinessStrategy types along with their
// own custom readiness condition.
//
// NB: This function is deliberately not added to
// internal/apis/acme/v1/defaults.go because it is not suitable to be called by
// the defaulting webhook. We don't want to confuse users who CREATE ACME Issuer
// or ClusterIssuer objects only to find that when they GET their issuer it is
// bloated with default SelfCheck and readiness gate fields. These fields are
// for power users who do not want to use the default SelfCheck settings.
func setDefaults_ACMEChallengeSolver(obj *v1.ACMEChallengeSolver) {
	if obj.ReadinessStrategy == nil {
		obj.ReadinessStrategy = &v1.ChallengeReadinessStrategy{}
	}
	if pointer.AllPtrFieldsNil(obj.ReadinessStrategy) {
		obj.ReadinessStrategy.SelfCheck = &v1.ChallengeSelfCheckReadinessStrategy{}
	}
	setDefaults_ChallengeDelayedAcceptReadinessStrategy(obj.ReadinessStrategy.DelayedAccept)
	if obj.ReadinessGates == nil {
		var gate *v1.ChallengeReadinessGate
		switch {
		case obj.ReadinessStrategy.SelfCheck != nil:
			gate = &v1.ChallengeReadinessGate{ConditionType: v1.ChallengConditionSelfCheckSucceeded}
		case obj.ReadinessStrategy.DelayedAccept != nil:
			gate = &v1.ChallengeReadinessGate{ConditionType: v1.ChallengConditionDelayedAcceptTimeoutReached}
		}
		if gate != nil {
			obj.ReadinessGates = append(obj.ReadinessGates, *gate)
		}
	}
}

const defaultDelayedAcceptTimeout = time.Second * 30

func setDefaults_ChallengeDelayedAcceptReadinessStrategy(obj *v1.ChallengeDelayedAcceptReadinessStrategy) {
	if obj == nil {
		return
	}
	if obj.Timeout.Duration == 0 {
		obj.Timeout.Duration = defaultDelayedAcceptTimeout
	}
}
