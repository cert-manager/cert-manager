/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package venafi

import (
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/Venafi/vcert/pkg/venafi/fake"
)

type fakeConnector struct {
	*fake.Connector

	PingFunc                  func() error
	ReadZoneConfigurationFunc func(string) (*endpoint.ZoneConfiguration, error)
	RetrieveCertificateFunc   func(*certificate.Request) (*certificate.PEMCollection, error)
	RequestCertificateFunc    func(*certificate.Request, string) (string, error)
	RenewCertificateFunc      func(*certificate.RenewalRequest) (string, error)
}

func (f fakeConnector) Default() *fakeConnector {
	if f.Connector == nil {
		f.Connector = fake.NewConnector(true, nil)
	}
	return &f
}

func (f *fakeConnector) Ping() (err error) {
	if f.PingFunc != nil {
		return f.PingFunc()
	}
	return f.Connector.Ping()
}

func (f *fakeConnector) ReadZoneConfiguration(zone string) (config *endpoint.ZoneConfiguration, err error) {
	if f.ReadZoneConfigurationFunc != nil {
		return f.ReadZoneConfigurationFunc(zone)
	}
	return f.Connector.ReadZoneConfiguration(zone)
}

func (f *fakeConnector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {
	if f.RetrieveCertificateFunc != nil {
		return f.RetrieveCertificateFunc(req)
	}
	return f.Connector.RetrieveCertificate(req)
}

func (f *fakeConnector) RequestCertificate(req *certificate.Request, zone string) (requestID string, err error) {
	if f.RequestCertificateFunc != nil {
		return f.RequestCertificateFunc(req, zone)
	}
	return f.Connector.RequestCertificate(req, zone)
}

func (f *fakeConnector) RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error) {
	if f.RenewCertificateFunc != nil {
		return f.RenewCertificateFunc(req)
	}
	return f.Connector.RenewCertificate(req)
}
