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
	"context"
	"crypto/x509"
	"errors"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/cloud"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

type cloudAuthenticator struct {
	secretKey string
	store     CredentialStore
	cloud     *cloud.Connector
}

var _ authenticator = &cloudAuthenticator{}

func (o *cloudAuthenticator) Authenticate() error {
	data, err := o.store.Load(context.TODO())
	if err != nil {
		return err
	}
	auth := &endpoint.Authentication{
		APIKey: string(data[o.secretKey]),
	}
	if err := o.cloud.Authenticate(auth); err != nil {
		return err
	}
	return nil
}

func (o *cloudAuthenticator) RotateCredentials() error {
	return errors.New("Credential rotation is not implemented for Venafi Cloud")
}

func newCloudConnector(cfg *cmapi.VenafiCloud, zone string) (*cloud.Connector, error) {
	var connectionTrustBundle *x509.CertPool
	return cloud.NewConnector(cfg.URL, zone, false, connectionTrustBundle)
}

func newCloud(cfg *cmapi.VenafiCloud, zone string, credentialStore CredentialStore) (*Venafi, error) {
	connector, err := newCloudConnector(cfg, zone)
	if err != nil {
		return nil, err
	}
	return &Venafi{
		vcertClient: connector,
		authenticator: &cloudAuthenticator{
			secretKey: cfg.APITokenSecretRef.Key,
			store:     credentialStore,
			cloud:     connector,
		},
	}, nil
}
