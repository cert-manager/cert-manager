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

package healthz

import (
	"fmt"
	"net/http"
	"time"

	"k8s.io/utils/clock"
)

const maxClockSkew = 5 * time.Minute

// The clockHealthAdaptor implements the HealthChecker interface.
// It checks the system clock is in sync with the internal monotonic clock.
// This is important because the internal monotonic clock is used to trigger certificate
// reconciles for renewals. If the monotonic clock is out of sync with the system clock
// then renewals might not be triggered in time. Ideally we would trigger renewals based
// on the system clock, but this is not (yet) possible in Go.
// See https://github.com/golang/go/issues/35012
//
// A clock skew can be caused by:
//  1. The system clock being adjusted
//     -> this, e.g., happens when ntp adjusts the system clock
//  2. Pausing the process (e.g., with SIGSTOP)
//     -> the monotonic clock will stop, but the system clock will continue
//     -> this, e.g., happens when you pause a VM/ hibernate a laptop
//
// Small clock skews of < 5m are allowed, because they can happen when the system clock is
// adjusted. However, we do compound the clock skew over time, so that if the clock skew
// is small but constant, it will eventually fail the health check.
type clockHealthAdaptor struct {
	clock              clock.Clock
	startTimeReal      time.Time
	startTimeMonotonic time.Time
}

func NewClockHealthAdaptor(c clock.Clock) *clockHealthAdaptor {
	now := c.Now()
	return &clockHealthAdaptor{
		clock:              c,
		startTimeReal:      now.Round(0), // .Round(0) removes the monotonic part from the time
		startTimeMonotonic: now,
	}
}

func (c *clockHealthAdaptor) skew() time.Duration {
	now := c.clock.Now()
	realDuration := now.Sub(c.startTimeReal)
	monotonicDuration := now.Sub(c.startTimeMonotonic)

	return (realDuration - monotonicDuration).Abs()
}

// Name returns the name of the health check we are implementing.
func (l *clockHealthAdaptor) Name() string {
	return "clockHealth"
}

// Check is called by the healthz endpoint handler.
// It fails (returns an error) when the system clock is out of sync with the
// internal monotonic clock by more than the maxClockSkew.
func (l *clockHealthAdaptor) Check(req *http.Request) error {
	if skew := l.skew(); skew > maxClockSkew {
		return fmt.Errorf("the system clock is out of sync with the internal monotonic clock by %v, which is more than the allowed %v", skew, maxClockSkew)
	}
	return nil
}
