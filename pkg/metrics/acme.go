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
	"k8s.io/apimachinery/pkg/types"

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
	for _, status := range challengeValidStatuses {
		value := 0.0
		if string(challenge.Status.State) == string(status) {
			value = 1.0
		}

		m.certificateChallengeStatus.With(prometheus.Labels{
			"status":     string(status),
			"reason":     challenge.Status.Reason,
			"domain":     challenge.Spec.DNSName,
			"name":       challenge.Name,
			"namespace":  challenge.Namespace,
			"type":       string(challenge.Spec.Type),
			"processing": fmt.Sprint(challenge.Status.Processing),
		}).Set(value)
	}
}

func (m *Metrics) RemoveChallengeStatus(key types.NamespacedName) {
	ns, name := key.Namespace, key.Name
	m.certificateChallengeStatus.DeletePartialMatch(prometheus.Labels{
		"name":      name,
		"namespace": ns,
	})
}
