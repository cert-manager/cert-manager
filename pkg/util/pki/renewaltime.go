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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
)

// RenewalTimeFunc is a custom function type for calculating renewal time of a certificate.
type RenewalTimeFunc func(time.Time, time.Time, *metav1.Duration, *int32, *apiv1.CertificateRenewal) (*metav1.Time, error)

// RenewalTime calculates renewal time for a certificate.
// If renewBefore is non-nil and less than the certificate's lifetime, renewal
// time will be the computed renewBefore period before expiry.
// If renewBeforePercentage is non-nil and in the range (0,100), renewal time
// will be the computed period before expiry based on the renewBeforePercentage
// value and certificate lifetime.
// Default renewal time is 2/3 through certificate's lifetime.
func RenewalTime(notBefore, notAfter time.Time, renewBefore *metav1.Duration, renewBeforePercentage *int32, renewalSpec *apiv1.CertificateRenewal) (*metav1.Time, error) {
	// 1. Start calculation of desired renewal time based on renewBefore and renewBeforePercentage.
	// 1.1: Calculate how long before expiry a cert should be renewed
	actualDuration := notAfter.Sub(notBefore)

	actualRenewBefore := desiredRenewalTime(actualDuration, renewBefore, renewBeforePercentage)

	// 1.2: Calculate when a cert should be renewed
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

	// 2. If there is no renewal spec then just return the desired renewal time calculated above.
	if renewalSpec == nil {
		return &rt, nil
	}

	switch renewalSpec.Policy {
	case apiv1.CertificateRenewalPolicyDisabled:
		return nil, nil
	case apiv1.CertificateRenewalPolicyRenewBefore:
		return applyRenewBeforeWithWindows(notAfter, notBefore, rt.Time, renewalSpec.Windows)
	default:
		return nil, fmt.Errorf("unsupported renewal policy: %s", renewalSpec.Policy)
	}
}

// desiredRenewalTime calculates how far before expiry a certificate should be renewed.
// If renewBefore is non-nil and less than the certificate's lifetime, renewal
// time will be the computed renewBefore period before expiry.
// If renewBeforePercentage is non-nil and in the range (0,100), renewal time
// will be the computed period before expiry based on the renewBeforePercentage
// and actualDuration values.
// Default is 2/3 through certificate's lifetime.

// Note that this function used to be called RenewBefore and was an exported function which would expose the renewal time.
// Currently, this function calculates the desired renewal time and feeds into the renewal windows logic called above.
func desiredRenewalTime(actualDuration time.Duration, renewBefore *metav1.Duration, renewBeforePercentage *int32) time.Duration {
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

// applyRenewBeforeWithWindows calculates effective renewal time with windows in it. We want the logic to be as follows:
// Take in the desiredRenewalTime from the function above and look forward and backward to find a desirable time which satisfies
// the cron window along with the cronSeconds duration. If we find a time that is before the renewalTime we return that first.
func applyRenewBeforeWithWindows(notAfter, notBefore, desiredRenewalTime time.Time, windows []apiv1.CertificateRenewalWindows) (*metav1.Time, error) {
	var (
		bestBefore *time.Time
		bestAfter  *time.Time
	)

	if len(windows) == 0 {
		return &metav1.Time{Time: desiredRenewalTime}, nil
	}

	for _, w := range windows {
		loc := time.UTC
		if w.Timezone != "" {
			if tz, err := time.LoadLocation(w.Timezone); err == nil {
				loc = tz
			} else {
				// This shouldn't get triggered as we validate timezones in the validation webhook.
				return nil, fmt.Errorf("error parsing timezone in window %s", err.Error())
			}
		}

		cronSched, err := util.CronParse(w.Cron, loc.String())
		if err != nil {
			return nil, fmt.Errorf("error parsing cron in window %s", err.Error())
		}

		// Any renewal logic should only start after notBefore and before notAfter. Bounds are [notBefore - dur, notAfter + dur)
		searchMin := notBefore.Add(-w.WindowDuration.Duration)
		searchMax := notAfter.Add(w.WindowDuration.Duration)

		bestBefore = findBeforeDesired(cronSched, searchMin, searchMax, desiredRenewalTime, bestBefore, w.WindowDuration.Duration)
		bestAfter = findAfterDesired(cronSched, searchMin, searchMax, desiredRenewalTime, bestAfter, w.WindowDuration.Duration)
	}

	if bestBefore != nil {
		return &metav1.Time{Time: *bestBefore}, nil
	}

	if bestAfter != nil {
		return &metav1.Time{Time: *bestAfter}, nil
	}

	return nil, fmt.Errorf("cannot find a time with the given windows for: %s", desiredRenewalTime.String())
}

// bsFindEarliestWindowBeforeDesired performs a binary search over time to find
// the latest cron window start S such that:
//
//	minTime <= S < maxTime
//
// where S is a time produced by sched.Next(..).
func bsFindLatestWindowBeforeDesired(sched util.CronSchedule, minTime, maxTime time.Time) *time.Time {
	if !minTime.Before(maxTime) {
		return nil
	}

	// If the first instance that matches the cron is after the max bound then we don't have a earliest window before desired renewal.
	if sched.Next(minTime.Add(-time.Second)).After(maxTime) {
		return nil
	}

	low := minTime
	high := maxTime

	// We binary search on the time range [low, high), maintaining the invariant:
	//
	//   There exists at least one cron start S such that:
	//       low <= S <= maxTime
	//
	// and S is produced by sched.Next(..).
	for high.Sub(low) > time.Second {
		mid := low.Add(high.Sub(low) / 2)
		next := sched.Next(mid)

		if next.After(maxTime) {
			high = mid
		} else {
			low = mid
		}
	}

	last := sched.Next(low.Add(-time.Second))
	if last.After(maxTime) {
		return nil
	}

	return &last
}

// findBeforeDesired returns a time that matches the cron schedule before the desiredRenewalTime. This function makes use of a binary search
// algorithm, with the bounds defined by searchMin and searchMax (desiredRenewalTime if it's before searchMax), to find a time which matches the cron schedule.
// if the desiredRenewalTime is in [lastStart, lastStart+duration) we just return that else we return lastStart+duration.
func findBeforeDesired(cronSched util.CronSchedule, searchMin, searchMax, desiredRenewalTime time.Time, bestBefore *time.Time, duration time.Duration) *time.Time {
	if desiredRenewalTime.Before(searchMin) {
		return nil
	}
	var beforeMax time.Time
	if desiredRenewalTime.Before(searchMax) {
		beforeMax = desiredRenewalTime
	} else {
		beforeMax = searchMax
	}
	lastStart := bsFindLatestWindowBeforeDesired(cronSched, searchMin, beforeMax)
	if lastStart != nil {
		end := lastStart.Add(duration)

		var candidateBefore time.Time
		if !desiredRenewalTime.Before(*lastStart) && desiredRenewalTime.Before(end) {
			candidateBefore = desiredRenewalTime
		} else {
			candidateBefore = end
		}

		// This is done to ensure that any candidateBefore is not before the desired renewal time.
		if !candidateBefore.Before(desiredRenewalTime) {
			if bestBefore == nil || candidateBefore.After(*bestBefore) {
				c := candidateBefore
				bestBefore = &c
			}
		}
	}

	return bestBefore
}

// findAfterDesired returns the first instance of time that matches the cronSched after the desiredRenewalTime.
func findAfterDesired(cronSched util.CronSchedule, searchMin, searchMax, desiredRenewalTime time.Time, bestAfter *time.Time, duration time.Duration) *time.Time {
	var afterMin time.Time
	if desiredRenewalTime.After(searchMin) {
		afterMin = desiredRenewalTime
	} else {
		afterMin = searchMin
	}
	start := cronSched.Next(afterMin.Add(-time.Second))
	if start.After(searchMax) {
		return nil
	}

	end := start.Add(duration)

	var candidateAfter time.Time
	switch {
	case !desiredRenewalTime.Before(start) && desiredRenewalTime.Before(end):
		candidateAfter = desiredRenewalTime
	case desiredRenewalTime.Before(start):
		candidateAfter = start
	default:
		candidateAfter = time.Time{}
	}

	// This check ensures that candidateAfter is never before the desiredRenewalTime
	if !candidateAfter.IsZero() && !candidateAfter.Before(desiredRenewalTime) {
		if bestAfter == nil || candidateAfter.Before(*bestAfter) {
			c := candidateAfter
			bestAfter = &c
		}
	}

	return bestAfter
}
