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

package fake

import (
	"crypto/rsa"

	acmepkg "github.com/jetstack/cert-manager/pkg/acme"
	acme "github.com/jetstack/cert-manager/pkg/acme/client"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

// Helper implements a simple fake structure that implements the Helper
// interface.
// This is useful during unit tests where an instance of a Helper must be
// injected into the controller in order to mock out the ACME client interface.

type Helper struct {
	ClientForIssuerFunc func(cmapi.GenericIssuer) (acme.Interface, error)
	ReadPrivateKeyFunc  func(cmmeta.SecretKeySelector, string) (*rsa.PrivateKey, error)
}

var _ acmepkg.Helper = &Helper{}

func (f *Helper) ClientForIssuer(i cmapi.GenericIssuer) (acme.Interface, error) {
	return f.ClientForIssuerFunc(i)
}

func (f *Helper) ReadPrivateKey(sel cmmeta.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
	return f.ReadPrivateKeyFunc(sel, ns)
}
