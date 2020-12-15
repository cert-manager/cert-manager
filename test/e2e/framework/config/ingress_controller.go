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

import (
	"flag"
)

type IngressController struct {
	// Domain is a domain name that can be used during e2e tests.
	// This domain should have records for *.example.com and example.com pointing
	// to the IP of the ingress controller's Service resource.
	Domain string

	// IngressClass of the ingress controller under test, used for the HTTP01
	// ACME validation tests.
	IngressClass string
}

func (n *IngressController) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&n.Domain, "ingress-controller-domain", "ingress-nginx.http01.example.com", "The domain name used during ACME DNS01 validation tests. "+
		"All subdomains of this domain must also resolve to the IP of the ingress controller's Service.")
	fs.StringVar(&n.IngressClass, "ingress-controller-class", "nginx", "Ingress class of the ingress controller under test, used for the HTTP01 ACME validation tests.")
}

func (n *IngressController) Validate() []error {
	return nil
}
