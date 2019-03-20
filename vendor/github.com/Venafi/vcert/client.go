/*
 * Copyright 2018 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vcert

import (
	"crypto/x509"
	"fmt"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/Venafi/vcert/pkg/venafi/cloud"
	"github.com/Venafi/vcert/pkg/venafi/fake"
	"github.com/Venafi/vcert/pkg/venafi/tpp"
)

func NewClient(cfg *Config) (endpoint.Connector, error) {
	var err error

	var connectionTrustBundle *x509.CertPool
	if cfg.ConnectionTrust != "" {
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, fmt.Errorf("failed to parse PEM trust bundle")
		}
	}

	var connector endpoint.Connector
	switch cfg.ConnectorType {
	case endpoint.ConnectorTypeCloud:
		connector = cloud.NewConnector(cfg.LogVerbose, connectionTrustBundle)
	case endpoint.ConnectorTypeTPP:
		connector = tpp.NewConnector(cfg.LogVerbose, connectionTrustBundle)
	case endpoint.ConnectorTypeFake:
		connector = fake.NewConnector(cfg.LogVerbose, connectionTrustBundle)
	default:
		return nil, fmt.Errorf("ConnectorType is not defined")
	}

	if cfg.BaseUrl != "" {
		connector.SetBaseURL(cfg.BaseUrl)
	}
	connector.SetZone(cfg.Zone)

	err = connector.Authenticate(cfg.Credentials)
	if err != nil {
		return nil, err
	}
	return connector, nil
}
