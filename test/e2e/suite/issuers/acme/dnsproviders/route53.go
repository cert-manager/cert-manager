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

package dnsproviders

import (
	"fmt"
	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/util/errors"
)

type Route53 struct {
	details    Details
	nameserver string
}

func (r *Route53) Setup(c *config.Config) error {
	if c.Addons.ACMEServer.DNSProvider != "route-53" {
		return errors.NewSkip(fmt.Errorf("skipping Route53 tests as DNS provider is set to %s",
			c.Addons.ACMEServer.DNSProvider,
		))
	}
	r.nameserver = c.Addons.ACMEServer.DNSServer
	r.details.BaseDomain = c.Addons.IngressController.Domain
	r.details.ProviderConfig = cmacme.ACMEChallengeSolverDNS01{
		Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
			HostedZoneID: c.Addons.ACMEServer.Route53Zone,
			Region:       c.Addons.ACMEServer.Route53Region,
		},
	}
	return nil
}

// Provision will create a copy of the DNS provider credentials in a secret in
// the APIServer, and return a portion of an Issuer that can be used to
// utilise these credentials in tests.
func (r *Route53) Provision() error {
	return nil
}

func (r *Route53) Deprovision() error {
	return nil
}

func (r *Route53) Details() *Details {
	return &r.details
}

func (r *Route53) SupportsGlobal() bool {
	return false
}
