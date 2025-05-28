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
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// ObserveACMERequestDuration increases bucket counters for that ACME client duration.
func (m *Metrics) ObserveACMERequestDuration(duration time.Duration, labels ...string) {
	m.acmeClientRequestDurationSeconds.WithLabelValues(labels...).Observe(duration.Seconds())
}

// IncrementACMERequestCount increases the acme client request counter.
func (m *Metrics) IncrementACMERequestCount(labels ...string) {
	m.acmeClientRequestCount.WithLabelValues(labels...).Inc()
}

func (m *Metrics) UpdateChallengeStatus(challenge *acmev1.Challenge) {
	value := 0.0

	for _, status := range challengeValidStatuses {
		if string(challenge.Status.State) == string(status) {
			value = 1.0
			break
		}
	}
	m.certificateChallengeStatus.With(prometheus.Labels{
		"status":     string(challenge.Status.State),
		"reason":     challenge.Status.Reason,
		"domain":     challenge.Spec.DNSName,
		"type":       string(challenge.Spec.Type),
		"id":         string(challenge.GetUID()),
		"processing": fmt.Sprint(challenge.Status.Processing),
	}).Set(value)
}

func (m *Metrics) RemoveChallengeStatus(challenge *acmev1.Challenge) {
	m.certificateChallengeStatus.DeletePartialMatch(prometheus.Labels{
		"id": string(challenge.GetUID()),
	})
}
