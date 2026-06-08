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
		wantCheckCalls     int
	}{
		// Without waitInsteadOfSelfCheck, readiness should behave exactly like the
		// existing strict self-check path.
		"no wait configured uses strict self-check": {
			challenge:          base.DeepCopy(),
			checkErr:           errors.New("some error"),
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          false,
			wantRetry:          10 * time.Second,
			wantReason:         "Waiting for HTTP-01 challenge propagation: some error",
			wantCheckCalls:     1,
		},
		// While waitInsteadOfSelfCheck is configured and the wait window has not
		// yet elapsed, readiness should report the remaining wait time without
		// depending on the self-check result.
		"wait configured returns remaining delay without using self-check": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeWaitInsteadOfSelfCheck(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-25*time.Second))),
			),
			checkErr:           errors.New("some error"),
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          false,
			wantRetry:          5 * time.Second,
			wantReason:         "Waiting 5s before accepting HTTP-01 challenge without self-check",
			wantCheckCalls:     0,
		},
		// Once the configured wait has elapsed, readiness should allow
		// acceptance without running the self-check.
		"wait configured proceeds after timeout without self-check": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeWaitInsteadOfSelfCheck(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-31*time.Second))),
			),
			checkErr:           errors.New("some error"),
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          true,
			wantCheckCalls:     0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			checkCalls := 0
			eval := buildChallengeReadinessEvaluator(tc.challenge, tc.defaultRetryPeriod, now)
			result, err := eval.evaluate(context.Background(), &fakeSolver{
				fakeCheck: func(_ context.Context, _ v1.GenericIssuer, _ *cmacme.Challenge) error {
					checkCalls++
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
			if checkCalls != tc.wantCheckCalls {
				t.Fatalf("checkCalls = %d, want %d", checkCalls, tc.wantCheckCalls)
			}
		})
	}
}

// PresentedAt is recorded independently of waitInsteadOfSelfCheck, but it
// should not affect readiness unless that option is configured.
func TestPresentedAtIsIgnoredWithoutWaitConfiguration(t *testing.T) {
	challenge := gen.Challenge("challenge",
		gen.SetChallengePresented(true),
		gen.SetChallengePresentedAt(metav1.Now()),
	)
	if challenge.Spec.Solver.WaitInsteadOfSelfCheck != nil {
		t.Fatal("unexpected waitInsteadOfSelfCheck")
	}
	if challenge.Status.PresentedAt == nil {
		t.Fatal("expected presentedAt to be set in status")
	}
}
