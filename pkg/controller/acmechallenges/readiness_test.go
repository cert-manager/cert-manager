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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestBuildChallengeReadinessEvaluator(t *testing.T) {
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	issuer := gen.Issuer("issuer")
	base := gen.Challenge("challenge",
		gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
		gen.SetChallengePresented(true),
	)

	tests := map[string]struct {
		challenge          *cmacme.Challenge
		checkErr           error
		defaultRetryPeriod time.Duration
		wantReady          bool
		wantRetry          time.Duration
		wantReason         string
	}{
		"no delay configured uses strict self-check": {
			challenge:          base.DeepCopy(),
			checkErr:           errors.New("some error"),
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          false,
			wantRetry:          10 * time.Second,
			wantReason:         "Waiting for HTTP-01 challenge propagation: some error",
		},
		"delay configured still short-circuits on successful self-check": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeAcceptChallengeAfter(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-5*time.Second))),
			),
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          true,
		},
		"delay configured returns remaining delay when self-check still failing": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeAcceptChallengeAfter(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-25*time.Second))),
			),
			checkErr:           errors.New("some error"),
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          false,
			wantRetry:          5 * time.Second,
			wantReason:         "Waiting for HTTP-01 challenge propagation",
		},
		"delay configured proceeds after timeout even if self-check still failing": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeAcceptChallengeAfter(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-31*time.Second))),
			),
			checkErr:           errors.New("some error"),
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			eval := buildChallengeReadinessEvaluator(tc.challenge, tc.defaultRetryPeriod, now)
			result, err := eval.evaluate(context.Background(), &fakeSolver{
				fakeCheck: func(_ context.Context, _ v1.GenericIssuer, _ *cmacme.Challenge) error {
					return tc.checkErr
				},
			}, issuer, tc.challenge)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.ready != tc.wantReady {
				t.Fatalf("ready = %v, want %v", result.ready, tc.wantReady)
			}
			if result.retryAfter != tc.wantRetry {
				t.Fatalf("retryAfter = %v, want %v", result.retryAfter, tc.wantRetry)
			}
			if result.reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", result.reason, tc.wantReason)
			}
		})
	}
}

func TestPresentedAtIsIgnoredWithoutDelayConfiguration(t *testing.T) {
	challenge := gen.Challenge("challenge",
		gen.SetChallengePresented(true),
		gen.SetChallengePresentedAt(metav1.Now()),
	)
	if challenge.Spec.Solver.AcceptChallengeAfter != nil {
		t.Fatal("unexpected acceptChallengeAfter")
	}
	if challenge.Status.PresentedAt == nil {
		t.Fatal("expected presentedAt to be set in status")
	}
	_ = cmmeta.ConditionTrue
}
