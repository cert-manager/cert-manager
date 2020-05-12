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

package acme

import (
	"crypto/rsa"
	"fmt"

	"github.com/jetstack/cert-manager/pkg/acme/accounts"
	acme "github.com/jetstack/cert-manager/pkg/acme/client"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
)

var (
	accountRegistry = accounts.NewDefaultRegistry()
)

// This file implements a basic cache for ACME clients that can be used to
// obtain a reference to an ACME client.
// This can be accessed via the 'helper' defined in helper.go, or directly with
// the ClientWithKey function below.

// ClientWithKey will construct a new ACME client for the provided Issuer, using
// the given RSA private key.
func ClientWithKey(iss cmapi.GenericIssuer, pk *rsa.PrivateKey) (acme.Interface, error) {
	acmeSpec := iss.GetSpec().ACME
	if acmeSpec == nil {
		return nil, fmt.Errorf("issuer %q is not an ACME issuer. Ensure the 'acme' stanza is correctly specified on your Issuer resource", iss.GetObjectMeta().Name)
	}
	uid := string(iss.GetUID())
	cl, err := accountRegistry.GetClient(uid)
	if err == accounts.ErrNotFound {
		accountRegistry.AddClient(uid, *acmeSpec, pk)
		return accountRegistry.GetClient(uid)
	}
	return cl, err
}

func ClearClientCache() {
	cs := accountRegistry.ListClients()
	for uid := range cs {
		accountRegistry.RemoveClient(uid)
	}
}
