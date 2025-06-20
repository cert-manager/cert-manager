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

package metrics

import (
	"time"
)

// ObserveACMERequestDuration increases bucket counters for that ACME client duration.
func (m *Metrics) ObserveACMERequestDuration(duration time.Duration, labels ...string) {
	m.acmeClientRequestDurationSeconds.WithLabelValues(labels...).Observe(duration.Seconds())
}

// IncrementACMERequestCount increases the acme client request counter.
func (m *Metrics) IncrementACMERequestCount(labels ...string) {
	m.acmeClientRequestCount.WithLabelValues(labels...).Inc()
}
