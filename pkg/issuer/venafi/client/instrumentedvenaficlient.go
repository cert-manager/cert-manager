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

package client

import (
	"time"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/go-logr/logr"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
)

type instrumentedConnector struct {
	conn    connector
	metrics *metrics.Metrics
	logger  *logr.Logger
}

var _ connector = instrumentedConnector{}

func newInstrumentedConnector(conn connector, metrics *metrics.Metrics, log logr.Logger) connector {
	return instrumentedConnector{
		conn:    conn,
		metrics: metrics,
		logger:  &log,
	}
}

func (ic instrumentedConnector) ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error) {
	start := time.Now()
	ic.logger.V(logf.TraceLevel).Info("calling ReadZoneConfiguration")
	config, err := ic.conn.ReadZoneConfiguration()
	labels := []string{"read_zone_configuration"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return config, err
}

func (ic instrumentedConnector) RequestCertificate(req *certificate.Request) (string, error) {
	start := time.Now()
	ic.logger.V(logf.TraceLevel).Info("calling RequestCertificate")
	reqID, err := ic.conn.RequestCertificate(req)
	labels := []string{"request_certificate"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return reqID, err
}

func (ic instrumentedConnector) RetrieveCertificate(req *certificate.Request) (*certificate.PEMCollection, error) {
	start := time.Now()
	ic.logger.V(logf.TraceLevel).Info("calling RetrieveCertificate")
	pemCollection, err := ic.conn.RetrieveCertificate(req)
	labels := []string{"retrieve_certificate"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return pemCollection, err
}

func (ic instrumentedConnector) Ping() error {
	start := time.Now()
	ic.logger.V(logf.TraceLevel).Info("calling Ping")
	err := ic.conn.Ping()
	labels := []string{"ping"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return err
}

func (ic instrumentedConnector) RenewCertificate(req *certificate.RenewalRequest) (string, error) {
	start := time.Now()
	ic.logger.V(logf.TraceLevel).Info("calling RenewCertificate")
	reqID, err := ic.conn.RenewCertificate(req)
	labels := []string{"renew_certificate"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return reqID, err
}
