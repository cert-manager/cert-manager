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
		challenge                *cmacme.Challenge
		checkErr                 error
		defaultRetryPeriod       time.Duration
		wantReady                bool
		wantRetry                time.Duration
		wantReason               string
		wantCheckCalls           int
		wantSelfCheckSucceededAt *time.Time
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
		// Regression test for https://github.com/cert-manager/cert-manager/issues/7834:
		// the delay is measured from the first successful self-check, not from
		// presentation. On first success the full delay must be waited.
		"delayBeforeAccept records first self-check success and waits full delay": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeDelayBeforeAccept(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-5*time.Second))),
			),
			checkErr:           nil,
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          false,
			wantRetry:          10 * time.Second,
			wantReason:         "Waiting 30s before accepting HTTP-01 challenge",
			wantCheckCalls:     1,
			wantSelfCheckSucceededAt: func() *time.Time {
				ts := now
				return &ts
			}(),
		},
		// Even when the presentation-based delay has already elapsed, a first
		// successful self-check must still wait the full delay. This is the
		// core race from #7834: local DNS may take longer than delayBeforeAccept
		// to propagate, so basing the deadline on presentation would accept
		// immediately.
		"delayBeforeAccept waits full delay even when presentation delay already elapsed": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeDelayBeforeAccept(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-31*time.Second))),
			),
			checkErr:           nil,
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          false,
			wantRetry:          10 * time.Second,
			wantReason:         "Waiting 30s before accepting HTTP-01 challenge",
			wantCheckCalls:     1,
			wantSelfCheckSucceededAt: func() *time.Time {
				ts := now
				return &ts
			}(),
		},
		// Once the self-check has been succeeding long enough, acceptance proceeds.
		"delayBeforeAccept proceeds after delay since self-check success when self-check passes": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeDelayBeforeAccept(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-60*time.Second))),
				gen.SetChallengeSelfCheckSucceededAt(metav1.NewTime(now.Add(-31*time.Second))),
			),
			checkErr:           nil,
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          true,
			wantCheckCalls:     1,
			wantSelfCheckSucceededAt: func() *time.Time {
				ts := now.Add(-31 * time.Second)
				return &ts
			}(),
		},
		// A failing self-check still blocks acceptance and clears any
		// previously recorded success so the delay restarts on next success.
		"delayBeforeAccept clears success timestamp when self-check fails": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeDelayBeforeAccept(metav1.Duration{Duration: 30 * time.Second}),
				gen.SetChallengePresentedAt(metav1.NewTime(now.Add(-60*time.Second))),
				gen.SetChallengeSelfCheckSucceededAt(metav1.NewTime(now.Add(-25*time.Second))),
			),
			checkErr:                 errors.New("some error"),
			defaultRetryPeriod:       10 * time.Second,
			wantReady:                false,
			wantRetry:                10 * time.Second,
			wantReason:               "Waiting for HTTP-01 challenge propagation: some error",
			wantCheckCalls:           1,
			wantSelfCheckSucceededAt: nil,
		},
		// Remaining delay is capped by the controller retry period so the
		// challenge is requeued promptly.
		"delayBeforeAccept caps retryAfter at default retry period": {
			challenge: gen.ChallengeFrom(base,
				gen.SetChallengeDelayBeforeAccept(metav1.Duration{Duration: 60 * time.Second}),
				gen.SetChallengeSelfCheckSucceededAt(metav1.NewTime(now.Add(-5*time.Second))),
			),
			checkErr:           nil,
			defaultRetryPeriod: 10 * time.Second,
			wantReady:          false,
			wantRetry:          10 * time.Second,
			wantReason:         "Waiting 55s before accepting HTTP-01 challenge",
			wantCheckCalls:     1,
			wantSelfCheckSucceededAt: func() *time.Time {
				ts := now.Add(-5 * time.Second)
				return &ts
			}(),
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
			if tc.wantSelfCheckSucceededAt != nil {
				if tc.challenge.Status.SelfCheckSucceededAt == nil {
					t.Fatalf("SelfCheckSucceededAt = nil, want %v", *tc.wantSelfCheckSucceededAt)
				}
				if !tc.challenge.Status.SelfCheckSucceededAt.Time.Equal(*tc.wantSelfCheckSucceededAt) {
					t.Fatalf("SelfCheckSucceededAt = %v, want %v", tc.challenge.Status.SelfCheckSucceededAt.Time, *tc.wantSelfCheckSucceededAt)
				}
			} else if tc.challenge.Spec.Solver.DelayBeforeAccept != nil && tc.checkErr != nil {
				// On self-check failure the timestamp must be cleared.
				if tc.challenge.Status.SelfCheckSucceededAt != nil {
					t.Fatalf("SelfCheckSucceededAt = %v, want nil after self-check failure", tc.challenge.Status.SelfCheckSucceededAt.Time)
				}
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
