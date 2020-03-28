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

	"github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type readinessStrategy interface {
	ready(context.Context) (time.Duration, *cmacme.ChallengeCondition)
}

type selfCheck struct {
	ch          *cmacme.Challenge
	issuer      cmapi.GenericIssuer
	solver      solver
	retryPeriod time.Duration
}

func (o *selfCheck) ready(ctx context.Context) (time.Duration, *cmacme.ChallengeCondition) {
	condition := &cmacme.ChallengeCondition{
		Type:   cmacme.ChallengConditionSelfCheckSucceeded,
		Status: cmmeta.ConditionTrue,
	}
	if err := o.solver.Check(ctx, o.issuer, o.ch); err != nil {
		condition.Status = cmmeta.ConditionFalse
		condition.Message = fmt.Sprintf("Waiting for %s challenge propagation: %s", o.ch.Spec.Type, err)
	}
	return o.retryPeriod, condition
}

type delayedAccept struct {
	ch          *cmacme.Challenge
	currentTime time.Time
}

func delayedAcceptReady(currentTime, referenceTime time.Time, delay time.Duration) (time.Duration, *cmacme.ChallengeCondition) {
	condition := &cmacme.ChallengeCondition{
		Type:   cmacme.ChallengConditionDelayedAcceptTimeoutReached,
		Status: cmmeta.ConditionTrue,
	}
	timeAfterWhichToAcceptChallenge := referenceTime.Add(delay)
	timeRemaining := timeAfterWhichToAcceptChallenge.Sub(currentTime)
	if timeRemaining > 0 {
		condition.Status = cmmeta.ConditionFalse
		condition.Message = fmt.Sprintf(
			"Waiting until %s before accepting challenge, to allow time for challenge resources to be deployed",
			timeAfterWhichToAcceptChallenge,
		)
	}
	return timeRemaining, condition
}

func (o *delayedAccept) ready(_ context.Context) (time.Duration, *cmacme.ChallengeCondition) {
	strategy := o.ch.Spec.Solver.ReadinessStrategy.DelayedAccept
	referenceTime := o.currentTime
	presentedCondition := util.GetChallengeCondition(o.ch, cmacme.ChallengConditionPresented)
	if presentedCondition != nil && presentedCondition.Status == cmmeta.ConditionTrue {
		referenceTime = presentedCondition.LastTransitionTime.Time
	}
	return delayedAcceptReady(o.currentTime, referenceTime, strategy.Timeout.Duration)
}

type noop struct{}

func (_ *noop) ready(_ context.Context) (time.Duration, *cmacme.ChallengeCondition) {
	return time.Duration(0), nil
}

func readinessStrategyForChallenge(ch *cmacme.Challenge) (readinessStrategy, error) {
	switch {
	case ch.Spec.Solver.ReadinessStrategy.SelfCheck != nil:
		return &selfCheck{}, nil
	case ch.Spec.Solver.ReadinessStrategy.DelayedAccept != nil:
		return &delayedAccept{}, nil
	case ch.Spec.Solver.ReadinessStrategy.None != nil:
		return &noop{}, nil
	default:
		return nil, fmt.Errorf("invalid empty readinessStrategy: %#v", ch.Spec.Solver.ReadinessStrategy)
	}
}
