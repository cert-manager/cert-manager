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
type RenewalTimeFunc func(time.Time, time.Time, *metav1.Duration, *int32) *metav1.Time

// RenewalTime calculates renewal time for a certificate.
// If renewBefore is non-nil and less than the certificate's lifetime, renewal
// time will be the computed renewBefore period before expiry.
// If renewBeforePercentage is non-nil and in the range (0,100), renewal time
// will be the computed period before expiry based on the renewBeforePercentage
// value and certificate lifetime.
// Default renewal time is 2/3 through certificate's lifetime.
func RenewalTime(notBefore, notAfter time.Time, renewBefore *metav1.Duration, renewBeforePercentage *int32) *metav1.Time {
	// 1. Calculate how long before expiry a cert should be renewed
	actualDuration := notAfter.Sub(notBefore)

	actualRenewBefore := RenewBefore(actualDuration, renewBefore, renewBeforePercentage)

	// 2. Calculate when a cert should be renewed

	// Truncate the renewal time to nearest second. This is important
	// because the renewal time also gets stored on Certificate's status
	// where it is truncated to the nearest second. We use the renewal time
	// from Certificate's status to determine when the Certificate will be
	// added to the queue to be renewed, but then re-calculate whether it
	// needs to be renewed _now_ using this function, so returning a
	// non-truncated value here would potentially cause Certificates to be
	// re-queued for renewal earlier than the calculated renewal time thus
	// causing Certificates to not be automatically renewed. See
	// https://github.com/cert-manager/cert-manager/pull/4399.
	rt := metav1.NewTime(notAfter.Add(-1 * actualRenewBefore).Truncate(time.Second))
	return &rt
}

// RenewBefore calculates how far before expiry a certificate should be renewed.
// If renewBefore is non-nil and less than the certificate's lifetime, renewal
// time will be the computed renewBefore period before expiry.
// If renewBeforePercentage is non-nil and in the range (0,100), renewal time
// will be the computed period before expiry based on the renewBeforePercentage
// and actualDuration values.
// Default is 2/3 through certificate's lifetime.
func RenewBefore(actualDuration time.Duration, renewBefore *metav1.Duration, renewBeforePercentage *int32) time.Duration {
	// If spec.renewBefore or spec.renewBeforePercentage was set (and is
	// valid) respect that. We don't want to prevent users from renewing
	// longer lived certs more frequently.
	if renewBefore != nil && renewBefore.Duration > 0 && renewBefore.Duration < actualDuration {
		return renewBefore.Duration
	} else if renewBeforePercentage != nil && *renewBeforePercentage > 0 && *renewBeforePercentage < 100 {
		return actualDuration * time.Duration(*renewBeforePercentage) / 100
	}

	// Otherwise, default to renewing 2/3 through certificate's lifetime.
	return actualDuration / 3
}
