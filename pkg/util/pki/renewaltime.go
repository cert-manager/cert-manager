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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RenewalTimeFunc is a custom function type for calculating renewal time of a certificate.
type RenewalTimeFunc func(time.Time, time.Time, *metav1.Duration) *metav1.Time

// RenewalTime calculates renewal time for a certificate. Default renewal time
// is 2/3 through certificate's lifetime. If user has configured
// spec.renewBefore, renewal time will be renewBefore period before expiry
// (unless that is after the expiry).
func RenewalTime(notBefore, notAfter time.Time, renewBeforeOverride *metav1.Duration) *metav1.Time {
	// 1. Calculate how long before expiry a cert should be renewed
	actualDuration := notAfter.Sub(notBefore)

	renewBefore := actualDuration / 3

	// If spec.renewBefore was set (and is less than duration)
	// respect that. We don't want to prevent users from renewing
	// longer lived certs more frequently.
	if renewBeforeOverride != nil && renewBeforeOverride.Duration < actualDuration {
		renewBefore = renewBeforeOverride.Duration
	}

	// 2. Calculate when a cert should be renewed

	// Truncate the renewal time to nearest second. This is important
	// because the renewal time also gets stored on Certificate's status
	// where it is truncated to the nearest second. We use the renewal time
	// from Certificate's status to determine when the Certificate will be
	// added to the queue to be renewed, but then re-calculate whether it
	// needs to be renewed _now_ using this function- so returning a
	// non-truncated value here would potentially cause Certificates to be
	// re-queued for renewal earlier than the calculated renewal time thus
	// causing Certificates to not be automatically renewed. See
	// https://github.com/cert-manager/cert-manager/pull/4399.
	rt := metav1.NewTime(notAfter.Add(-1 * renewBefore).Truncate(time.Second))
	return &rt
}
