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

package config

import "flag"

type Gateway struct {
	// Domain is a domain name that is used during e2e tests to solve
	// ACME HTTP-01 Challenges.
	// It should have suitable records set that resolve *.<domain> to
	// the IP of the Gateway's Service.
	Domain string

	// Labels is a comma separated list of key=value labels set on the
	// HTTPRoutes created by the Gateway API solver
	Labels string
}

func (g *Gateway) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(
		&g.Domain,
		"gateway-domain",
		"gateway.http01.example.com",
		"The domain name used during e2e tests to solve HTTP-01 "+
			"challenges. This must resolve to the IP of the Gateway's service.",
	)
	fs.StringVar(
		&g.Labels,
		"gateway-httproute-labels",
		"acme=solver",
		"Labels is a comma separated list of key=value labels set on the "+
			"HTTPRoutes created by the Gateway API solver",
	)
}

func (g *Gateway) Validate() []error {
	return nil
}
