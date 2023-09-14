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

type clockHealthAdaptor struct {
	clock              clock.Clock
	startTimeReal      time.Time
	startTimeMonotonic time.Time
}

func NewClockHealthAdaptor(c clock.Clock) *clockHealthAdaptor {
	return &clockHealthAdaptor{
		clock:              c,
		startTimeReal:      c.Now().Round(0), // .Round(0) removes the monotonic part from the time
		startTimeMonotonic: c.Now(),
	}
}

func (c *clockHealthAdaptor) skew() time.Duration {
	realDuration := c.clock.Since(c.startTimeReal)
	monotonicDuration := c.clock.Since(c.startTimeMonotonic)

	if monotonicDuration > realDuration {
		return monotonicDuration - realDuration
	}

	return realDuration - monotonicDuration
}

// Name returns the name of the health check we are implementing.
func (l *clockHealthAdaptor) Name() string {
	return "clockHealth"
}

// Check is called by the healthz endpoint handler.
// It fails (returns an error) if we own the lease but had not been able to renew it.
func (l *clockHealthAdaptor) Check(req *http.Request) error {
	if skew := l.skew(); skew > 1*time.Minute {
		return fmt.Errorf("the system clock is out of sync with the internal monotonic clock by %v, which is more than the allowed 1m", skew)
	}
	return nil
}
