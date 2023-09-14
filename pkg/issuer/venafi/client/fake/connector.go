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

package fake

import (
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/fake"
)

type Connector struct {
	*fake.Connector

	PingFunc                  func() error
	ReadZoneConfigurationFunc func() (*endpoint.ZoneConfiguration, error)
	RetrieveCertificateFunc   func(*certificate.Request) (*certificate.PEMCollection, error)
	RequestCertificateFunc    func(*certificate.Request) (string, error)
	RenewCertificateFunc      func(*certificate.RenewalRequest) (string, error)
}

func (f Connector) Default() *Connector {
	if f.Connector == nil {
		f.Connector = fake.NewConnector(true, nil)
	}
	return &f
}

func (f *Connector) Ping() (err error) {
	if f.PingFunc != nil {
		return f.PingFunc()
	}
	return f.Connector.Ping()
}

func (f *Connector) ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error) {
	if f.ReadZoneConfigurationFunc != nil {
		return f.ReadZoneConfigurationFunc()
	}
	return f.Connector.ReadZoneConfiguration()
}

func (f *Connector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {
	if f.RetrieveCertificateFunc != nil {
		return f.RetrieveCertificateFunc(req)
	}
	return f.Connector.RetrieveCertificate(req)
}

func (f *Connector) RequestCertificate(req *certificate.Request) (requestID string, err error) {
	if f.RequestCertificateFunc != nil {
		return f.RequestCertificateFunc(req)
	}
	return f.Connector.RequestCertificate(req)
}

func (f *Connector) RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error) {
	if f.RenewCertificateFunc != nil {
		return f.RenewCertificateFunc(req)
	}
	return f.Connector.RenewCertificate(req)
}
