/*
Copyright 2026 The cert-manager Authors.

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

package pki

import (
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"

	"hegel.dev/go/hegel"
)

// TestRenewalTimeWithinCertLifetime checks that, without a renewal spec, the
// renewal time always falls within [notBefore, notAfter] for any certificate
// lifetime and any combination of renewBefore and renewBeforePercentage,
// including out-of-range values which must fall back to the 2/3 default.
func TestRenewalTimeWithinCertLifetime(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		notBefore := time.Unix(hegel.Draw(ht, hegel.Integers[int64](0, 4_000_000_000)), 0).UTC()
		lifetime := time.Duration(hegel.Draw(ht, hegel.Integers[int64](1, 10*365*24*3600))) * time.Second
		notAfter := notBefore.Add(lifetime)

		var renewBefore *metav1.Duration
		if rb := hegel.Draw(ht, hegel.Optional(hegel.Integers[int64](-3600, 20*365*24*3600))); rb != nil {
			renewBefore = &metav1.Duration{Duration: time.Duration(*rb) * time.Second}
		}
		pct := hegel.Draw(ht, hegel.Optional(hegel.Integers[int32](-10, 110)))

		rt, err := RenewalTime(notBefore, notAfter, renewBefore, pct, nil)
		if err != nil {
			ht.Fatalf("RenewalTime returned error: %v", err)
		}
		if rt == nil {
			ht.Fatalf("RenewalTime returned nil time without a Disabled policy")
		}
		if rt.Time.Before(notBefore) || rt.Time.After(notAfter) {
			ht.Fatalf("renewal time %s outside certificate lifetime [%s, %s] (renewBefore=%v, pct=%v)",
				rt.Time, notBefore, notAfter, renewBefore, pct)
		}
	}, hegel.WithTestCases(5000))
}

// TestRenewalTimeWithWindows checks invariants of the renewal windows logic
// for a single daily cron window: the windowed renewal time must never be
// earlier than the plain (no-windows) renewal time, and must be either that
// plain time (when it falls inside a window) or the start of a cron window.
// The lifetime is kept >= 7 days so that a daily cron always yields a window
// between the plain renewal time and notAfter, hence no error is acceptable.
func TestRenewalTimeWithWindows(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		notBefore := time.Unix(hegel.Draw(ht, hegel.Integers[int64](0, 4_000_000_000)), 0).UTC()
		lifetime := time.Duration(hegel.Draw(ht, hegel.Integers[int64](7*24*3600, 90*24*3600))) * time.Second
		notAfter := notBefore.Add(lifetime)

		cron := fmt.Sprintf("%d %d * * *",
			hegel.Draw(ht, hegel.Integers(0, 59)),
			hegel.Draw(ht, hegel.Integers(0, 23)))
		windowDur := time.Duration(hegel.Draw(ht, hegel.Integers[int64](60, 24*3600))) * time.Second

		plain, err := RenewalTime(notBefore, notAfter, nil, nil, nil)
		if err != nil {
			ht.Fatalf("RenewalTime without windows returned error: %v", err)
		}

		rt, err := RenewalTime(notBefore, notAfter, nil, nil, &apiv1.CertificateRenewal{
			Policy: apiv1.CertificateRenewalPolicyRenewBefore,
			Windows: []apiv1.CertificateRenewalWindows{{
				Timezone:       "UTC",
				Cron:           cron,
				WindowDuration: &metav1.Duration{Duration: windowDur},
			}},
		})
		if err != nil {
			ht.Fatalf("RenewalTime with cron %q window %s returned error: %v", cron, windowDur, err)
		}

		if rt.Time.Before(plain.Time) {
			ht.Fatalf("windowed renewal time %s is before plain renewal time %s (cron %q, window %s)",
				rt.Time, plain.Time, cron, windowDur)
		}
		if rt.Time.After(notAfter.Add(windowDur)) {
			ht.Fatalf("windowed renewal time %s is after the last possible window end %s (cron %q, window %s)",
				rt.Time, notAfter.Add(windowDur), cron, windowDur)
		}
		sched, err := util.CronParse(cron, "UTC")
		if err != nil {
			ht.Fatalf("failed to parse cron %q: %v", cron, err)
		}
		if !rt.Time.Equal(plain.Time) && !sched.Next(rt.Time.Add(-time.Second)).Equal(rt.Time) {
			ht.Fatalf("windowed renewal time %s is neither the plain renewal time %s nor a cron occurrence (cron %q, window %s)",
				rt.Time, plain.Time, cron, windowDur)
		}
	}, hegel.WithTestCases(5000))
}
