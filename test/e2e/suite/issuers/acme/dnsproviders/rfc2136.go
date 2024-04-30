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

package dnsproviders

import (
	"context"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/config"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

type RFC2136 struct {
	details    Details
	nameserver string
}

func (b *RFC2136) Setup(c *config.Config, _ ...addon.AddonTransferableData) (addon.AddonTransferableData, error) {
	b.nameserver = c.Addons.ACMEServer.DNSServer
	return nil, nil
}

// Provision will create a copy of the DNS provider credentials in a secret in
// the APIServer, and return a portion of an Issuer that can be used to
// utilise these credentials in tests.
func (b *RFC2136) Provision(_ context.Context) error {
	b.details.ProviderConfig = cmacme.ACMEChallengeSolverDNS01{
		RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
			Nameserver: b.nameserver,
		},
	}
	b.details.BaseDomain = "dns01.example.com"
	return nil
}

func (b *RFC2136) Deprovision(_ context.Context) error {
	return nil
}

func (b *RFC2136) Details() *Details {
	return &b.details
}

func (b *RFC2136) SupportsGlobal() bool {
	return false
}
