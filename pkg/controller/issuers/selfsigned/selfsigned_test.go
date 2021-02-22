/*
Copyright 2021 The cert-manager Authors.

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

package selfsigned

import (
	"testing"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestImplements(t *testing.T) {
	tests := map[string]struct {
		issuer        cmapi.GenericIssuer
		expImplements bool
	}{
		// Issuer Kind
		"if nil issuer, exp not implements": {
			issuer:        gen.Issuer("test"),
			expImplements: false,
		},
		"if selfsigned issuer, exp implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			expImplements: true,
		},
		"if ca issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerCA(cmapi.CAIssuer{}),
			),
			expImplements: false,
		},
		"if vault issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			expImplements: false,
		},
		"if venafi issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
			),
			expImplements: false,
		},
		"if acme issuer, exp not implements": {
			issuer: gen.Issuer("test",
				gen.SetIssuerACME(cmacme.ACMEIssuer{}),
			),
			expImplements: false,
		},

		// ClusterIssuer Kind
		"if nil cluster issuer, exp not implements": {
			issuer:        gen.ClusterIssuer("test"),
			expImplements: false,
		},
		"if selfsigned cluster issuer, exp implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			),
			expImplements: true,
		},
		"if ca cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerCA(cmapi.CAIssuer{}),
			),
			expImplements: false,
		},
		"if vault cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVault(cmapi.VaultIssuer{}),
			),
			expImplements: false,
		},
		"if venafi cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerVenafi(cmapi.VenafiIssuer{}),
			),
			expImplements: false,
		},
		"if acme cluster issuer, exp not implements": {
			issuer: gen.ClusterIssuer("test",
				gen.SetIssuerACME(cmacme.ACMEIssuer{}),
			),
			expImplements: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			i := new(SelfSigned)
			if impl := i.Implements(test.issuer); impl != test.expImplements {
				t.Errorf("unexpected implements, exp=%t got=%t",
					test.expImplements, impl)
			}
		})
	}
}
