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

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/go-logr/logr"
)

type instrumentedConnector struct {
	conn    connector
	metrics *metrics.Metrics
	// TODO: actually use this logger or remove it
	logger *logr.Logger
}

var _ connector = instrumentedConnector{}

func newInstumentedConnector(conn connector, metrics *metrics.Metrics) connector {
	return instrumentedConnector{
		conn:    conn,
		metrics: metrics,
	}
}

func (ic instrumentedConnector) ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error) {
	start := time.Now()
	config, err := ic.conn.ReadZoneConfiguration()
	// TODO: how do the key value pairs work for the labels work?
	labels := []string{"read_zone_configuration"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return config, err
}

func (ic instrumentedConnector) RequestCertificate(req *certificate.Request) (string, error) {
	start := time.Now()
	reqID, err := ic.conn.RequestCertificate(req)
	labels := []string{"request_certificate"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return reqID, err
}

func (ic instrumentedConnector) RetrieveCertificate(req *certificate.Request) (*certificate.PEMCollection, error) {
	start := time.Now()
	pemCollection, err := ic.conn.RetrieveCertificate(req)
	labels := []string{"retrieve_certificate"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return pemCollection, err
}

func (ic instrumentedConnector) Ping() error {
	start := time.Now()
	err := ic.conn.Ping()
	labels := []string{"ping"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return err
}

func (ic instrumentedConnector) RenewCertificate(req *certificate.RenewalRequest) (string, error) {
	start := time.Now()
	reqID, err := ic.conn.RenewCertificate(req)
	labels := []string{"renew_certificate"}
	ic.metrics.ObserveVenafiRequestDuration(time.Since(start), labels...)
	return reqID, err
}
