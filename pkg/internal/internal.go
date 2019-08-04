/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package internal

import (
	"time"

	vault "github.com/hashicorp/vault/api"
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type VaultClientBuilder func(string, corelisters.SecretLister, v1alpha1.GenericIssuer) (Vault, error)

type Vault interface {
	Sign(csrPEM []byte, duration time.Duration) (certPEM []byte, caPEM []byte, err error)
	Sys() *vault.Sys
}

type VaultClient interface {
	NewRequest(method, requestPath string) *vault.Request
	RawRequest(r *vault.Request) (*vault.Response, error)
	SetToken(v string)
	Token() string
	Sys() *vault.Sys
}
