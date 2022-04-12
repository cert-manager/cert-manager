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
	"fmt"
	"time"

	"k8s.io/client-go/util/workqueue"

	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmapiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
)

type checkChallengeReadiness struct {
	syncStep
}

var _ syncStep = &checkChallengeReadiness{}

func (o *checkChallengeReadiness) Initialize(ctx context.Context, state *syncState) error {
	var subStep syncStep
	strategy := copyOfChallengeWithDefaultsApplied(state.challenge).Spec.Solver.ReadinessStrategy
	switch {
	case strategy.SelfCheck != nil:
		subStep = &selfCheck{}
	case strategy.DelayedAccept != nil:
		subStep = &delayedAccept{}
	case strategy.None != nil:
		subStep = &noop{}
	default:
		return fmt.Errorf("invalid empty readinessStrategy: %#v", strategy)
	}
	if err := subStep.Initialize(ctx, state); err != nil {
		return err
	}
	o.syncStep = subStep
	return nil
}

type selfCheck struct {
	issuer        cmapi.GenericIssuer
	solver        solver
	queue         workqueue.RateLimitingInterface
	retryInterval time.Duration
}

func (o *selfCheck) Initialize(_ context.Context, state *syncState) error {
	o.issuer = state.issuer
	o.solver = state.solver
	o.queue = state.controller.queue
	o.retryInterval = state.controller.DNS01CheckRetryPeriod
	return nil
}

func (o *selfCheck) Evaluate(_ context.Context, ch *cmacme.Challenge) (syncAction, error) {
	expectedCondition := cmacme.ChallengeCondition{
		Type:   cmacme.ChallengConditionSelfCheckSucceeded,
		Status: cmmeta.ConditionTrue,
	}
	if util.ChallengeHasCondition(ch, expectedCondition) {
		return nil, nil
	}
	return o, nil
}

func (o *selfCheck) Run(ctx context.Context, ch *cmacme.Challenge) error {
	condition := &cmacme.ChallengeCondition{
		Type:   cmacme.ChallengConditionSelfCheckSucceeded,
		Status: cmmeta.ConditionTrue,
	}
	if err := o.solver.Check(ctx, o.issuer, ch); err != nil {
		condition.Status = cmmeta.ConditionFalse
		condition.Message = fmt.Sprintf("Waiting for %s challenge propagation: %s", ch.Spec.Type, err)
		key, err := controllerpkg.KeyFunc(ch)
		if err != nil {
			panic("unexpected error")
		}
		o.queue.AddAfter(key, o.retryInterval)
	}
	cmapiutil.SetChallengeCondition(ch, ch.Generation, condition.Type, condition.Status, "ChallengeReadinessCheck", condition.Message)
	return nil
}

type delayedAccept struct {
	queue       workqueue.RateLimitingInterface
	currentTime time.Time
}

func (o *delayedAccept) Initialize(_ context.Context, state *syncState) error {
	o.queue = state.controller.queue
	o.currentTime = time.Now()
	return nil
}

func (o *delayedAccept) Evaluate(_ context.Context, ch *cmacme.Challenge) (syncAction, error) {
	expectedCondition := cmacme.ChallengeCondition{
		Type:   cmacme.ChallengConditionDelayedAcceptTimeoutReached,
		Status: cmmeta.ConditionTrue,
	}
	if util.ChallengeHasCondition(ch, expectedCondition) {
		return nil, nil
	}
	return o, nil
}

func (o *delayedAccept) Run(_ context.Context, ch *cmacme.Challenge) error {
	strategy := ch.Spec.Solver.ReadinessStrategy.DelayedAccept
	referenceTime := o.currentTime
	presentedCondition := util.GetChallengeCondition(ch, cmacme.ChallengConditionPresented)
	if presentedCondition != nil && presentedCondition.Status == cmmeta.ConditionTrue {
		referenceTime = presentedCondition.LastTransitionTime.Time
	}
	condition := &cmacme.ChallengeCondition{
		Type:   cmacme.ChallengConditionDelayedAcceptTimeoutReached,
		Status: cmmeta.ConditionTrue,
	}
	timeAfterWhichToAcceptChallenge := referenceTime.Add(strategy.Timeout.Duration)
	timeRemaining := timeAfterWhichToAcceptChallenge.Sub(o.currentTime)
	if timeRemaining > 0 {
		condition.Status = cmmeta.ConditionFalse
		condition.Message = fmt.Sprintf(
			"Waiting until %s before accepting challenge, to allow time for challenge resources to be deployed",
			timeAfterWhichToAcceptChallenge,
		)
		key, err := controllerpkg.KeyFunc(ch)
		if err != nil {
			panic("unexpected error")
		}
		o.queue.AddAfter(key, timeRemaining)
	}
	cmapiutil.SetChallengeCondition(ch, ch.Generation, condition.Type, condition.Status, "ChallengeReadinessCheck", condition.Message)
	return nil
}

type noop struct{}

func (_ *noop) Initialize(_ context.Context, _ *syncState) error {
	return nil
}

func (_ *noop) Evaluate(_ context.Context, _ *cmacme.Challenge) (syncAction, error) {
	return nil, nil
}
