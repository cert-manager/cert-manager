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

package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/internal/venafi/client/api"
)

// Interface implements a Venafi client
type Interface interface {
	RequestCertificate(csrPEM []byte, duration time.Duration, customFields []api.CustomField) (string, error)
	RetrieveCertificate(pickupID string, csrPEM []byte, duration time.Duration, customFields []api.CustomField) ([]byte, error)
	ReadZoneConfiguration() (*endpoint.ZoneConfiguration, error)
	Ping() error
	Authenticate() error
	RotateCredentials() error
}

// vcertClient exposes a subset of the vcert Connector interface to make stubbing
// out its functionality during tests easier.
type vcertClient interface {
	Ping() (err error)
	ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error)
	RequestCertificate(req *certificate.Request) (requestID string, err error)
	RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error)
	RenewCertificate(req *certificate.RenewalRequest) (requestID string, err error)
}

type authenticator interface {
	Authenticate() error
	RotateCredentials() error
}

// Venafi is a implementation of vcert library to manager certificates from TPP or Venafi Cloud
type Venafi struct {
	vcertClient
	authenticator
}

var _ Interface = &Venafi{}

var (
	ErrSecretNotFound       = errors.New("secret not found")
	ErrInvalidConfiguration = errors.New("invalid configuration")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrOauth                = fmt.Errorf("%w: oauth", ErrInvalidCredentials)
	ErrAccessTokenMissing   = fmt.Errorf("%w: access-token is missing", ErrOauth)
	ErrAccessTokenExpired   = fmt.Errorf("%w: access-token has expired", ErrOauth)
)

func New(venCfg *cmapi.VenafiIssuer, credentialStore CredentialStore) (Interface, error) {
	switch {
	case venCfg.TPP != nil:
		return newTPP(venCfg.TPP, venCfg.Zone, credentialStore)
	case venCfg.Cloud != nil:
		return newCloud(venCfg.Cloud, venCfg.Zone, credentialStore)
	default:
		panic("unsupported venafi config")
	}
}
