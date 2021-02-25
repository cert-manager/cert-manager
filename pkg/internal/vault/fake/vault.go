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
	"time"

	vault "github.com/hashicorp/vault/api"
	corelisters "k8s.io/client-go/listers/core/v1"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

type Vault struct {
	NewFn  func(string, corelisters.SecretLister, v1.GenericIssuer) (*Vault, error)
	SignFn func([]byte, time.Duration) ([]byte, []byte, error)
}

func New() *Vault {
	v := &Vault{
		SignFn: func([]byte, time.Duration) ([]byte, []byte, error) {
			return nil, nil, nil
		},
	}

	v.NewFn = func(string, corelisters.SecretLister, v1.GenericIssuer) (*Vault, error) {
		return v, nil
	}

	return v
}

func (v *Vault) Sign(csrPEM []byte, duration time.Duration) ([]byte, []byte, error) {
	return v.SignFn(csrPEM, duration)
}

func (v *Vault) WithSign(certPEM, caPEM []byte, err error) *Vault {
	v.SignFn = func([]byte, time.Duration) ([]byte, []byte, error) {
		return certPEM, caPEM, err
	}
	return v
}

func (v *Vault) WithNew(f func(string, corelisters.SecretLister, v1.GenericIssuer) (*Vault, error)) *Vault {
	v.NewFn = f
	return v
}

func (v *Vault) New(ns string, sl corelisters.SecretLister, iss v1.GenericIssuer) (*Vault, error) {
	_, err := v.NewFn(ns, sl, iss)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func (v *Vault) Sys() *vault.Sys {
	return new(vault.Sys)
}
