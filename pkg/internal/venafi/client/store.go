/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

// CredentialStore is used by the Venafi client to load and save credentials.
// The main implementation loads and saves from Kubernetes Secret resources.
// Allows the client to be tested without simulating interactions with the
// Kubernetes API.
type CredentialStore interface {
	Load(context.Context) (map[string][]byte, error)
	Save(context.Context, map[string][]byte) error
}

// secretStore loads and saves credentials to a single Secret
type secretStore struct {
	secretName   string
	secretLister corelisters.SecretNamespaceLister
	secretClient coreclient.SecretInterface
}

var _ CredentialStore = &secretStore{}

func (o *secretStore) loadSecret() (*corev1.Secret, error) {
	secret, err := o.secretLister.Get(o.secretName)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %q", ErrSecretNotFound, o.secretName)
		}
		return nil, fmt.Errorf("failed to get secret: %v", err)
	}
	return secret.DeepCopy(), nil
}

func (o *secretStore) Load(_ context.Context) (map[string][]byte, error) {
	secret, err := o.loadSecret()
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}
func (o *secretStore) Save(ctx context.Context, data map[string][]byte) error {
	secret, err := o.loadSecret()
	if err != nil {
		return nil
	}
	secret.Data = data
	_, err = o.secretClient.Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

// NewSecretStore hides the differences in the Secret references used in Venafi TPP and Cloud configurations.
func NewSecretStore(venCfg *cmapi.VenafiIssuer, secretLister corelisters.SecretNamespaceLister, secretClient coreclient.SecretInterface) CredentialStore {
	var secretName string
	switch {
	case venCfg.TPP != nil:
		secretName = venCfg.TPP.CredentialsRef.Name
	case venCfg.Cloud != nil:
		secretName = venCfg.Cloud.APITokenSecretRef.Name
	default:
		panic("unsupported venafi config")
	}
	return &secretStore{
		secretName:   secretName,
		secretLister: secretLister,
		secretClient: secretClient,
	}
}
