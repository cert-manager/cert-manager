/*
Copyright 2026 The cert-manager Authors.

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

package authority

import (
	"crypto/x509"
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricsNamespace = "certmanager"
	metricsSubsystem = "dynamic_serving"
)

// The metrics are shared by all DynamicAuthority instances in the process and
// are partitioned by the Secret resource storing the CA, so that e.g. the
// webhook serving certificate and the metrics serving certificate of the same
// component can be told apart.
var (
	caExpirationTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "ca_expiration_timestamp_seconds",
			Help: "The time after which the CA certificate used to sign dynamic serving certificates expires, " +
				"expressed in Unix Epoch Time. Labels: secret_namespace, secret_name (the Secret storing the CA).",
		},
		[]string{"secret_namespace", "secret_name"},
	)

	certificateExpirationTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "certificate_expiration_timestamp_seconds",
			Help: "The time after which the most recently signed dynamic serving certificate expires, " +
				"expressed in Unix Epoch Time. Labels: secret_namespace, secret_name (the Secret storing the signing CA).",
		},
		[]string{"secret_namespace", "secret_name"},
	)

	certificateSigningsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "certificate_signings_total",
			Help: "Total number of attempts to sign a dynamic serving certificate. Attempts made before the CA is available are not counted. " +
				"Labels: secret_namespace, secret_name (the Secret storing the signing CA), status (success/failure).",
		},
		[]string{"secret_namespace", "secret_name", "status"},
	)
)

// RegisterMetrics registers the metrics of all DynamicAuthority instances with
// the given registry. Registering with the same registry more than once is a
// no-op, but registering when a different collector with the same metrics is
// already registered returns an error.
func RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range collectors() {
		if err := reg.Register(c); err != nil {
			var are prometheus.AlreadyRegisteredError
			if !errors.As(err, &are) || are.ExistingCollector != c {
				return err
			}
		}
	}
	return nil
}

func collectors() []prometheus.Collector {
	return []prometheus.Collector{
		caExpirationTimestampSeconds,
		certificateExpirationTimestampSeconds,
		certificateSigningsTotal,
	}
}

func (d *DynamicAuthority) observeCA(caCert *x509.Certificate) {
	caExpirationTimestampSeconds.WithLabelValues(d.SecretNamespace, d.SecretName).Set(float64(caCert.NotAfter.Unix()))
}

func (d *DynamicAuthority) observeSign(cert *x509.Certificate, err error) {
	switch {
	case errors.Is(err, ErrCertificateNotAvailable):
		// The CA has not been loaded yet, which is expected while the
		// component is starting up.
	case err != nil:
		certificateSigningsTotal.WithLabelValues(d.SecretNamespace, d.SecretName, "failure").Inc()
	default:
		certificateSigningsTotal.WithLabelValues(d.SecretNamespace, d.SecretName, "success").Inc()
		certificateExpirationTimestampSeconds.WithLabelValues(d.SecretNamespace, d.SecretName).Set(float64(cert.NotAfter.Unix()))
	}
}
