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

// readinessEvaluation captures the result of evaluating whether a challenge
// should be accepted now or retried later.
type readinessEvaluation struct {
	ready      bool
	retryAfter time.Duration
	reason     string
}

// challengeReadinessEvaluator decides whether a presented challenge is ready
// to be accepted with the ACME server.
type challengeReadinessEvaluator interface {
	evaluate(ctx context.Context, solver solver, issuer cmapi.GenericIssuer, ch *cmacme.Challenge) (readinessEvaluation, error)
}

// selfCheckReadinessEvaluator preserves the existing behaviour of requiring a
// successful solver self-check before acceptance.
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

// waitInsteadOfSelfCheckReadinessEvaluator allows a challenge to become ready
// once a configured delay has elapsed since it was first presented, without
// running cert-manager's usual self-check.
type waitInsteadOfSelfCheckReadinessEvaluator struct {
	defaultRetryPeriod time.Duration
	now                time.Time
	wait               time.Duration
}

func (e waitInsteadOfSelfCheckReadinessEvaluator) evaluate(_ context.Context, _ solver, _ cmapi.GenericIssuer, ch *cmacme.Challenge) (readinessEvaluation, error) {
	if ch.Status.PresentedAt == nil {
		return readinessEvaluation{
			ready:      false,
			retryAfter: e.defaultRetryPeriod,
			reason:     fmt.Sprintf("Waiting %s before accepting %s challenge without self-check", e.wait, ch.Spec.Type),
		}, nil
	}

	deadline := ch.Status.PresentedAt.Add(e.wait)
	if !e.now.Before(deadline) {
		return readinessEvaluation{ready: true}, nil
	}

	remaining := deadline.Sub(e.now)

	return readinessEvaluation{
		ready:      false,
		retryAfter: min(remaining, e.defaultRetryPeriod),
		reason:     fmt.Sprintf("Waiting %s before accepting %s challenge without self-check", remaining, ch.Spec.Type),
	}, nil
}

// buildChallengeReadinessEvaluator constructs the readiness policy for a
// challenge from its solver configuration.
func buildChallengeReadinessEvaluator(ch *cmacme.Challenge, defaultRetryPeriod time.Duration, now time.Time) challengeReadinessEvaluator {
	if ch.Spec.Solver.WaitInsteadOfSelfCheck == nil {
		return selfCheckReadinessEvaluator{defaultRetryPeriod: defaultRetryPeriod}
	}
	return waitInsteadOfSelfCheckReadinessEvaluator{
		defaultRetryPeriod: defaultRetryPeriod,
		now:                now,
		wait:               ch.Spec.Solver.WaitInsteadOfSelfCheck.Duration,
	}
}
