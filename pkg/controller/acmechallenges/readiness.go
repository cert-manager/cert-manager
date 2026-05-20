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

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

type readinessEvaluation struct {
	ready      bool
	retryAfter time.Duration
	reason     string
}

type challengeReadinessEvaluator interface {
	evaluate(ctx context.Context, solver solver, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) (readinessEvaluation, error)
}

type selfCheckReadinessEvaluator struct {
	defaultRetryPeriod time.Duration
}

func (e selfCheckReadinessEvaluator) evaluate(ctx context.Context, solver solver, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) (readinessEvaluation, error) {
	err := solver.Check(ctx, issuer, ch)
	if err == nil {
		return readinessEvaluation{ready: true}, nil
	}
	return readinessEvaluation{
		ready:      false,
		retryAfter: e.defaultRetryPeriod,
		reason:     fmt.Sprintf("Waiting for %s challenge propagation: %s", ch.Spec.Type, err),
	}, nil
}

type delayAfterPresentationReadinessEvaluator struct {
	defaultRetryPeriod time.Duration
	now                time.Time
	delay              time.Duration
}

func (e delayAfterPresentationReadinessEvaluator) evaluate(_ context.Context, _ solver, _ cmapi.GenericIssuer, ch *cmacme.Challenge) (readinessEvaluation, error) {
	if ch.Status.PresentedAt == nil {
		return readinessEvaluation{
			ready:      false,
			retryAfter: e.defaultRetryPeriod,
			reason:     fmt.Sprintf("Waiting for %s challenge propagation", ch.Spec.Type),
		}, nil
	}

	deadline := ch.Status.PresentedAt.Add(e.delay)
	if !e.now.Before(deadline) {
		return readinessEvaluation{ready: true}, nil
	}

	remaining := min(deadline.Sub(e.now), e.defaultRetryPeriod)

	return readinessEvaluation{
		ready:      false,
		retryAfter: remaining,
		reason:     fmt.Sprintf("Waiting for %s challenge propagation", ch.Spec.Type),
	}, nil
}

type firstReadyEvaluator struct {
	evaluators []challengeReadinessEvaluator
}

func (e firstReadyEvaluator) evaluate(ctx context.Context, solver solver, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) (readinessEvaluation, error) {
	bestRetry := time.Duration(0)
	bestReason := ""
	for i, evaluator := range e.evaluators {
		result, err := evaluator.evaluate(ctx, solver, issuer, ch)
		if err != nil {
			return readinessEvaluation{}, err
		}
		if result.ready {
			return result, nil
		}
		if i == 0 || result.retryAfter < bestRetry {
			bestRetry = result.retryAfter
			bestReason = result.reason
		}
	}
	return readinessEvaluation{ready: false, retryAfter: bestRetry, reason: bestReason}, nil
}

func buildChallengeReadinessEvaluator(ch *cmacme.Challenge, defaultRetryPeriod time.Duration, now time.Time) challengeReadinessEvaluator {
	if ch.Spec.Solver.AcceptChallengeAfter == nil {
		return selfCheckReadinessEvaluator{defaultRetryPeriod: defaultRetryPeriod}
	}
	return firstReadyEvaluator{
		evaluators: []challengeReadinessEvaluator{
			selfCheckReadinessEvaluator{defaultRetryPeriod: defaultRetryPeriod},
			delayAfterPresentationReadinessEvaluator{
				defaultRetryPeriod: defaultRetryPeriod,
				now:                now,
				delay:              ch.Spec.Solver.AcceptChallengeAfter.Duration,
			},
		},
	}
}
