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

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/tools/cache"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// ObserveACMEChallengeStateChange denotes when an ACME challenge state change has occurred
func (m *Metrics) ObserveACMEChallengeStateChange(ch *cmacme.Challenge) {
	m.ObserveACMEChallengeStateChangeWithTime(ch, time.Now())
}

// ObserveACMEChallengeStateChangeWithTime denotes when an ACME challenge state change has occurred
func (m *Metrics) ObserveACMEChallengeStateChangeWithTime(ch *cmacme.Challenge, t time.Time) {
	labels := []string{
		ch.GetObjectMeta().GetName(),
		ch.GetObjectMeta().GetNamespace(),
		ch.Spec.IssuerRef.Name,
		ch.Spec.IssuerRef.Kind,
		ch.Spec.IssuerRef.Group,
		string(ch.Status.State),
	}
	m.certificateAcmeChallengeStatus.WithLabelValues(labels...).Set(float64(t.Unix()))
}

// ObserveACMEOrderStateChange denotes when an ACME order state change has occurred
func (m *Metrics) ObserveACMEOrderStateChange(o *cmacme.Order) {
	m.ObserveACMEOrderStateChangeWithTime(o, time.Now())
}

// ObserveACMEOrderStateChangeWithTime denotes when an ACME order state change has occurred as of time t
func (m *Metrics) ObserveACMEOrderStateChangeWithTime(o *cmacme.Order, t time.Time) {
	labels := []string{
		o.GetObjectMeta().GetName(),
		o.GetObjectMeta().GetNamespace(),
		o.Spec.IssuerRef.Name,
		o.Spec.IssuerRef.Kind,
		o.Spec.IssuerRef.Group,
		string(o.Status.State),
	}
	m.certificateAcmeOrderStatus.WithLabelValues(labels...).Set(float64(t.Unix()))
}

// ObserveACMEScheduled increases the counter for schedule ACME challenges
func (m *Metrics) ObserveACMEScheduled(count int, labels ...string) {
	m.acmeScheduled.WithLabelValues(labels...).Add(float64(count))
}

// ObserveACMERequestDuration increases bucket counters for that ACME client duration.
func (m *Metrics) ObserveACMERequestDuration(duration time.Duration, labels ...string) {
	m.acmeClientRequestDurationSeconds.WithLabelValues(labels...).Observe(duration.Seconds())
}

// IncrementACMERequestCount increases the acme client request counter.
func (m *Metrics) IncrementACMERequestCount(labels ...string) {
	m.acmeClientRequestCount.WithLabelValues(labels...).Inc()
}

// RemoveACMEObjects causees ACME metrics to not be exposed in prometheus.
func (m *Metrics) RemoveACMEObjects(key string) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		m.log.Error(err, "failed to get namespace and name from key")
		return
	}

	m.certificateAcmeChallengeStatus.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
	m.certificateAcmeOrderStatus.DeletePartialMatch(prometheus.Labels{"name": name, "namespace": namespace})
}
