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

// Package fake contains a fake Vault signer for use in tests
package fake

import (
	"time"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// Vault is a mock implementation of the Vault interface
type Vault struct {
	NewFn                           func(string, internalinformers.SecretLister, cmapi.GenericIssuer) (*Vault, error)
	SignFn                          func([]byte, time.Duration) ([]byte, []byte, error)
	IsVaultInitializedAndUnsealedFn func() error
}

// New returns a new fake Vault
func New() *Vault {
	v := &Vault{
		SignFn: func([]byte, time.Duration) ([]byte, []byte, error) {
			return nil, nil, nil
		},
		IsVaultInitializedAndUnsealedFn: func() error {
			return nil
		},
	}

	v.NewFn = func(string, internalinformers.SecretLister, cmapi.GenericIssuer) (*Vault, error) {
		return v, nil
	}

	return v
}

// Sign implements `vault.Interface`.
func (v *Vault) Sign(csrPEM []byte, duration time.Duration) ([]byte, []byte, error) {
	return v.SignFn(csrPEM, duration)
}

// WithSign sets the fake Vault's Sign function.
func (v *Vault) WithSign(certPEM, caPEM []byte, err error) *Vault {
	v.SignFn = func([]byte, time.Duration) ([]byte, []byte, error) {
		return certPEM, caPEM, err
	}
	return v
}

// WithNew sets the fake Vault's New function.
func (v *Vault) WithNew(f func(string, internalinformers.SecretLister, cmapi.GenericIssuer) (*Vault, error)) *Vault {
	v.NewFn = f
	return v
}

// New call NewFn and returns a pointer to the fake Vault.
func (v *Vault) New(ns string, sl internalinformers.SecretLister, iss cmapi.GenericIssuer) (*Vault, error) {
	_, err := v.NewFn(ns, sl, iss)
	if err != nil {
		return nil, err
	}

	return v, nil
}

// IsVaultInitializedAndUnsealed always returns nil
func (v *Vault) IsVaultInitializedAndUnsealed() error {
	return nil
}
