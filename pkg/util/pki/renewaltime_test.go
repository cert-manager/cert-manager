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

package pki

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	apiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

func TestRenewalTime(t *testing.T) {
	type scenario struct {
		notBefore           time.Time
		notAfter            time.Time
		renewBefore         *metav1.Duration
		renewBeforePct      *int32
		expectedRenewalTime *metav1.Time
	}
	now := time.Now().Truncate(time.Second)
	tests := map[string]scenario{
		"short lived cert, spec.renewBefore is not set": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 3),
			renewBefore:         nil,
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 2)},
		},
		"long lived cert, spec.renewBefore is not set": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 4380), // 6 months
			renewBefore:         nil,
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 2920)}, // renew in 4 months
		},
		"spec.renewBefore is set": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 24),
			renewBefore:         &metav1.Duration{Duration: time.Hour * 20},
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 4)},
		},
		"long lived cert, spec.renewBefore is set to renew every day": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 730),                    // 1 month
			renewBefore:         &metav1.Duration{Duration: time.Hour * 706}, // 1 month - 1 day
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 24)},
		},
		"spec.renewBefore is set, but would result in renewal time after expiry": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 24),
			renewBefore:         &metav1.Duration{Duration: time.Hour * 25},
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 16)},
		},
		"long lived cert, spec.renewBeforePercentage is set to renew 30% before expiry": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 730), // 1 month
			renewBeforePct:      ptr.To(int32(30)),
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 511)}, // 70% of 1 month
		},
		// This test case is here to show the scenario where users set
		// renewBefore to very slightly less than actual duration. This
		// will result in cert being renewed 'continuously'.
		"spec.renewBefore is set to a value slightly less than cert's duration": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour*24 + time.Minute*3),
			renewBefore:         &metav1.Duration{Duration: time.Hour * 24},
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Minute * 3)}, // renew in 3 minutes
		},
		// This test case is here to guard against an earlier bug where
		// a non-truncated renewal time returned from this function
		// caused certs to not be renewed.
		// See https://github.com/cert-manager/cert-manager/pull/4399
		"certificate's duration is skewed by a second": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 24).Add(time.Second * -1),
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 16).Add(time.Second * -1)},
		},
	}
	for n, s := range tests {
		t.Run(n, func(t *testing.T) {
			renewalTime, err := RenewalTime(s.notBefore, s.notAfter, s.renewBefore, s.renewBeforePct, nil)
			assert.Nil(t, err)
			assert.Equal(t, s.expectedRenewalTime, renewalTime, fmt.Sprintf("Expected renewal time: %v got: %v", s.expectedRenewalTime, renewalTime))
		})
	}
}

func TestRenewBefore(t *testing.T) {
	const duration = time.Hour * 3

	type scenario struct {
		renewBefore         *metav1.Duration
		renewBeforePct      *int32
		expectedRenewBefore time.Duration
	}

	tests := map[string]scenario{
		"spec.renewBefore and spec.renewBeforePercentage are not set": {
			renewBefore:         nil,
			expectedRenewBefore: time.Hour,
		},
		"spec.renewBeforePercentage is valid": {
			renewBeforePct:      ptr.To(int32(25)),
			expectedRenewBefore: 45 * time.Minute,
		},
		"spec.renewBeforePercentage is too large so default is used": {
			renewBeforePct:      ptr.To(int32(100)),
			expectedRenewBefore: time.Hour,
		},
		"spec.renewBeforePercentage is too small so default is used": {
			renewBeforePct:      ptr.To(int32(0)),
			expectedRenewBefore: time.Hour,
		},
		"spec.renewBefore is valid": {
			renewBefore:         &metav1.Duration{Duration: time.Hour * 1},
			expectedRenewBefore: time.Hour,
		},
		"spec.renewBefore is invalid so default is used": {
			renewBefore:         &metav1.Duration{Duration: time.Hour * 4},
			expectedRenewBefore: time.Hour,
		},
	}
	for n, s := range tests {
		t.Run(n, func(t *testing.T) {
			renewBefore := desiredRenewalTime(duration, s.renewBefore, s.renewBeforePct)
			assert.Equal(t, s.expectedRenewBefore, renewBefore, fmt.Sprintf("Expected renewBefore time: %v got: %v", s.expectedRenewBefore, renewBefore))
		})
	}
}

func midnightUTC(t time.Time) time.Time {
	y, m, d := t.Date()

	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func getNextWeekday(t time.Time, f func(time.Weekday) bool) time.Time {
	for {
		if f(t.Weekday()) {
			return t
		}

		t = t.AddDate(0, 0, 1)
	}
}

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("failed to load location %v", err)
	}
	return loc
}

// TestRenewalWithWindowsForRenewBefore tests renewal logic with windows for `RenewBefore` policy.
func TestRenewalWithWindowsForRenewBefore(t *testing.T) {
	type scenario struct {
		notBefore           time.Time
		notAfter            time.Time
		targetRenewalTime   time.Time
		expectedRenewalTime time.Time
		wantErr             bool
		renewalSpec         *apiv1.CertificateRenewal
	}

	now := time.Now().UTC().Truncate(time.Second)
	future := midnightUTC(now.AddDate(0, 0, 5))
	denverMDT := midnightUTC(time.Date(2026, time.March, 8, 0, 0, 0, 0, time.UTC))    // Approximate daylight savings start time. This is intentionally set to 2026 to avoid future changes to DST patterns breaking tests.
	denverMST := midnightUTC(time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)) // Approximate daylight savings end time
	tests := map[string]scenario{
		"single window, renewal time within window": {
			notAfter:            future.Add(48 * time.Hour),
			targetRenewalTime:   future.Add(10*time.Hour + 30*time.Minute),
			expectedRenewalTime: future.Add(24 * time.Hour).Add(-(13*time.Hour + 30*time.Minute)),
			notBefore:           midnightUTC(now.AddDate(0, 0, -10)),
			renewalSpec: &apiv1.CertificateRenewal{
				Policy: apiv1.CertificateRenewalPolicyRenewBefore,
				Windows: []apiv1.CertificateRenewalWindows{
					{
						Timezone:       time.UTC.String(),
						WindowDuration: &metav1.Duration{Duration: time.Hour * 2},
						Cron:           "0 10 * * *",
					},
				},
			},
		},
		"single window, time outside window": {
			notAfter:            future.Add(48 * time.Hour),
			targetRenewalTime:   future.Add(13 * time.Hour),
			notBefore:           midnightUTC(now.AddDate(0, 0, -10)),
			expectedRenewalTime: future.Add(24 * time.Hour).Add(10 * time.Hour),
			renewalSpec: &apiv1.CertificateRenewal{
				Policy: apiv1.CertificateRenewalPolicyRenewBefore,
				Windows: []apiv1.CertificateRenewalWindows{
					{
						Timezone:       time.UTC.String(),
						WindowDuration: &metav1.Duration{Duration: time.Hour * 2},
						Cron:           "0 10 * * *",
					},
				},
			},
		},
		"single window, renewal time before the window": {
			notBefore:           midnightUTC(now.AddDate(0, 0, -10)),
			notAfter:            future.Add(24 * time.Hour),
			targetRenewalTime:   future.Add(9 * time.Hour),
			expectedRenewalTime: future.Add(15 * time.Hour),
			renewalSpec: &apiv1.CertificateRenewal{
				Policy: apiv1.CertificateRenewalPolicyRenewBefore,
				Windows: []apiv1.CertificateRenewalWindows{
					{
						Timezone:       time.UTC.String(),
						WindowDuration: &metav1.Duration{Duration: time.Hour * 2},
						Cron:           "0 15 * * *",
					},
				},
			},
		},
		"multiple windows, weekday and weekend": {
			notBefore: midnightUTC(now.AddDate(0, 0, -10)),
			notAfter: getNextWeekday(future, func(w time.Weekday) bool {
				return w == time.Saturday
			}).Add(24 * time.Hour),
			targetRenewalTime: getNextWeekday(future, func(w time.Weekday) bool {
				return w == time.Saturday
			}).Add(6 * time.Hour),
			expectedRenewalTime: getNextWeekday(future, func(w time.Weekday) bool {
				return w == time.Saturday
			}).Add(10 * time.Hour),
			renewalSpec: &apiv1.CertificateRenewal{
				Policy: apiv1.CertificateRenewalPolicyRenewBefore,
				Windows: []apiv1.CertificateRenewalWindows{
					{
						Timezone:       time.UTC.String(),
						Cron:           "0 23 * * 1-5",
						WindowDuration: &metav1.Duration{Duration: time.Hour * 2},
					},
					{
						Timezone:       time.UTC.String(),
						Cron:           "0 10 * * 6,0",
						WindowDuration: &metav1.Duration{Duration: time.Hour * 4},
					},
				},
			},
		},
		"single window, renewal time within window, different timezone": {
			notAfter:            future.Add(48 * time.Hour),
			targetRenewalTime:   time.Date(future.Year(), future.Month(), future.Day(), 10, 30, 0, 0, mustLoc(t, "America/Phoenix")),
			expectedRenewalTime: time.Date(future.Year(), future.Month(), future.Day()+1, 0, 0, 0, 0, mustLoc(t, "America/Phoenix")).Add(-(13*time.Hour + 30*time.Minute)).UTC(),
			notBefore:           midnightUTC(now.AddDate(0, 0, -10)),
			renewalSpec: &apiv1.CertificateRenewal{
				Policy: apiv1.CertificateRenewalPolicyRenewBefore,
				Windows: []apiv1.CertificateRenewalWindows{
					{
						// Choosing America/Phoenix to avoid DST issues in test
						Timezone:       "America/Phoenix",
						Cron:           "0 10 * * *",
						WindowDuration: &metav1.Duration{Duration: time.Hour * 2},
					},
				},
			},
		},
		"single window, renewal time in daylight savings (on to off) time zone": {
			notAfter:            denverMST.Add(48 * time.Hour),
			targetRenewalTime:   time.Date(denverMST.Year(), denverMST.Month(), denverMST.Day()-1, 15, 30, 0, 0, mustLoc(t, "America/Denver")),
			expectedRenewalTime: time.Date(denverMST.Year(), denverMST.Month(), denverMST.Day()-1, 0, 0, 0, 0, mustLoc(t, "America/Denver")).Add((35*time.Hour + 0*time.Minute)).UTC(),
			notBefore:           midnightUTC(denverMDT.AddDate(0, 0, -10)),
			renewalSpec: &apiv1.CertificateRenewal{
				Policy: apiv1.CertificateRenewalPolicyRenewBefore,
				Windows: []apiv1.CertificateRenewalWindows{
					{
						Timezone:       "America/Denver",
						Cron:           "0 10 * * *",
						WindowDuration: &metav1.Duration{Duration: time.Hour * 2},
					},
				},
			},
		},
		"single window, renewal time outside of windows": {
			notAfter:            future.Add(24 * time.Hour),
			targetRenewalTime:   future.Add(13*time.Hour + 30*time.Minute),
			expectedRenewalTime: time.Time{},
			notBefore:           midnightUTC(now.AddDate(0, 0, -10)),
			wantErr:             true,
			renewalSpec: &apiv1.CertificateRenewal{
				Policy: apiv1.CertificateRenewalPolicyRenewBefore,
				Windows: []apiv1.CertificateRenewalWindows{
					{
						Timezone:       time.UTC.String(),
						Cron:           "0 10 * * *",
						WindowDuration: &metav1.Duration{Duration: time.Hour * 2},
					},
				},
			},
		},
	}

	for name, te := range tests {
		renewBefore := te.notAfter.Sub(te.targetRenewalTime)

		res, err := RenewalTime(te.notBefore, te.notAfter, &metav1.Duration{Duration: renewBefore}, nil, te.renewalSpec)

		if te.wantErr {
			assert.NotNil(t, err)
			assert.ErrorContains(t, err, "cannot find a time with the given windows for")

			var nilTime *metav1.Time = nil
			assert.Equal(t, nilTime, res, name)
			return
		}

		assert.Nil(t, err)
		assert.Equal(t, te.expectedRenewalTime, res.Time, name)
	}
}

func TestRenewalWithDisable(t *testing.T) {
	now := time.Now()
	notAfter := now.Add(time.Hour * 24)

	res, err := RenewalTime(now, notAfter, &metav1.Duration{Duration: 20 * time.Hour}, nil, &apiv1.CertificateRenewal{
		Policy: apiv1.CertificateRenewalPolicyDisabled,
	})

	assert.Nil(t, err)
	assert.Nil(t, res)
}
