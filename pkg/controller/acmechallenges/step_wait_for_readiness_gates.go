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

	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmapiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type waitForReadinessGates struct {
}

var _ syncStep = &waitForReadinessGates{}

func (o *waitForReadinessGates) Initialize(_ context.Context, _ *syncState) error {
	return nil
}

func (o *waitForReadinessGates) Evaluate(ctx context.Context, ch *cmacme.Challenge) (syncAction, error) {
	expectedCondition := cmacme.ChallengeCondition{
		Type:   cmacme.ChallengConditionAllReadinessGatesTrue,
		Status: cmmeta.ConditionTrue,
	}
	if util.ChallengeHasCondition(ch, expectedCondition) {
		return nil, nil
	}
	return o, nil
}

func (o *waitForReadinessGates) Run(ctx context.Context, ch *cmacme.Challenge) error {
	condition := &cmacme.ChallengeCondition{
		Type:   cmacme.ChallengConditionAllReadinessGatesTrue,
		Status: cmmeta.ConditionFalse,
	}
	if allReadinessGateConditionsAreTrue(ch) {
		condition.Status = cmmeta.ConditionTrue
	}
	cmapiutil.SetChallengeCondition(ch, ch.Generation, condition.Type, condition.Status, "ChallengeReadinessCheck", condition.Message)
	return nil
}
