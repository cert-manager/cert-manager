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
	"github.com/Venafi/vcert/v5/pkg/endpoint"

	"github.com/cert-manager/cert-manager/pkg/issuer/venafi/client/api"
)

type Venafi struct {
	PingFn                  func() error
	RequestCertificateFn    func(csrPEM []byte, customFields []api.CustomField) (string, error)
	RetrieveCertificateFn   func(pickupID string, csrPEM []byte, customFields []api.CustomField) ([]byte, error)
	ReadZoneConfigurationFn func() (*endpoint.ZoneConfiguration, error)
	VerifyCredentialsFn     func() error
}

func (v *Venafi) Ping() error {
	return v.PingFn()
}

func (v *Venafi) RequestCertificate(csrPEM []byte, customFields []api.CustomField) (string, error) {
	return v.RequestCertificateFn(csrPEM, customFields)
}

func (v *Venafi) RetrieveCertificate(pickupID string, csrPEM []byte, customFields []api.CustomField) ([]byte, error) {
	return v.RetrieveCertificateFn(pickupID, csrPEM, customFields)
}

func (v *Venafi) ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error) {
	return v.ReadZoneConfigurationFn()
}

func (v *Venafi) SetClient(endpoint.Connector) {}

// VerifyCredentials will return VerifyCredentialsFn if set, otherwise nil.
func (v *Venafi) VerifyCredentials() error {
	if v.VerifyCredentialsFn != nil {
		return v.VerifyCredentialsFn()
	}

	return nil
}
