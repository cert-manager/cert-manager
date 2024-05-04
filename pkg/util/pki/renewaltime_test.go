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
		"long lived cert, spec.renewBeforePercentage is set to renew 50% of the way": {
			notBefore:           now,
			notAfter:            now.Add(time.Hour * 730), // 1 month
			renewBeforePct:      ptr.To(int32(50)),
			expectedRenewalTime: &metav1.Time{Time: now.Add(time.Hour * 365)},
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
			renewalTime := RenewalTime(s.notBefore, s.notAfter, s.renewBefore, s.renewBeforePct)
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
			expectedRenewBefore: 135 * time.Minute,
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
			renewBefore := RenewBefore(duration, s.renewBefore, s.renewBeforePct)
			assert.Equal(t, s.expectedRenewBefore, renewBefore, fmt.Sprintf("Expected renewBefore time: %v got: %v", s.expectedRenewBefore, renewBefore))
		})
	}
}
