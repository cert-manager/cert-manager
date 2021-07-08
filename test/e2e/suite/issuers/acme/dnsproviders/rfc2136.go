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
	"fmt"

	corev1 "k8s.io/api/core/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/util/errors"
)

type RFC2136 struct {
	details    Details
	nameserver string
}

func (b *RFC2136) Setup(c *config.Config) error {
	if c.Addons.ACMEServer.DNSProvider != "rfc-2136" {
		return errors.NewSkip(fmt.Errorf("skipping RFC2136 tests as DNS provider is set to %s",
			c.Addons.ACMEServer.DNSProvider,
		))
	}
	b.nameserver = c.Addons.ACMEServer.DNSServer
	return nil
}

// Provision will create a copy of the DNS provider credentials in a secret in
// the APIServer, and return a portion of an Issuer that can be used to
// utilise these credentials in tests.
func (b *RFC2136) Provision(_ *corev1.Namespace) error {
	b.details.ProviderConfig = cmacme.ACMEChallengeSolverDNS01{
		RFC2136: &cmacme.ACMEIssuerDNS01ProviderRFC2136{
			Nameserver: b.nameserver,
		},
	}
	b.details.BaseDomain = "dns01.example.com"
	return nil
}

func (b *RFC2136) Deprovision() error {
	return nil
}

func (b *RFC2136) Details() *Details {
	return &b.details
}

func (b *RFC2136) SupportsGlobal() bool {
	return false
}
