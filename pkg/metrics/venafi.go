/*
Copyright 2022 The cert-manager Authors.

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

// ObserveVenafiRequestDuration increases bucket counters for that Venafi client duration.
func (m *Metrics) ObserveVenafiRequestDuration(duration time.Duration, labels ...string) {
	m.venafiClientRequestDurationSeconds.WithLabelValues(labels...).Observe(duration.Seconds())
}

// IncrementVenafiOAuthTokenRequestsTotal increments the OAuth token request counter with the given status.
// status must be either "success" or "failure".
func (m *Metrics) IncrementVenafiOAuthTokenRequestsTotal(status string) {
	m.venafiOAuthTokenRequestsTotal.WithLabelValues(status).Inc()
}

// ObserveVenafiOAuthTokenRequestDuration records the duration of an OAuth token request.
func (m *Metrics) ObserveVenafiOAuthTokenRequestDuration(duration time.Duration) {
	m.venafiOAuthTokenRequestDurationSecs.Observe(duration.Seconds())
}
