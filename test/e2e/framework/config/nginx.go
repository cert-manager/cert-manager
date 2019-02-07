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

package config

import (
	"flag"
	"fmt"
)

type Nginx struct {
	// Helm chart version to deploy during tests
	ChartVersion string

	Global NginxRuntimeConfig
}

// NginxRuntimeConfig is a copy of the runtime configuration for an instance of
// the nginx addon.
// It is copied to avoid dependency cycle issues, as the nginx addon depends
// upon this package for global configuration.
type NginxRuntimeConfig struct {
	// IPAddress is the IP address that the nginx-ingress service will be
	// exposed on.
	// This must be a part of the service CIDR, and must not already be allocated
	// else provisioning will fail.
	IPAddress string

	// Domain is a domain name that can be used during e2e tests.
	// This domain should have records for *.example.com and example.com pointing
	// to the IP listed above.
	Domain string
}

func (n *Nginx) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&n.ChartVersion, "nginx-ingress-chart-version", "0.29.1", "nginx-ingress chart version to use during tests")

	n.Global.AddFlags(fs)
}

func (n *Nginx) Validate() []error {
	var errs []error
	if n.ChartVersion == "" {
		errs = append(errs, fmt.Errorf("--nginx-ingress-chart-version must be specified"))
	}
	errs = append(errs, n.Global.Validate()...)
	return errs
}

func (n *NginxRuntimeConfig) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&n.IPAddress, "global-nginx-ingress-ip-address", "10.0.0.15", "The IP address to expose the shared nginx-ingress used during tests on.")
	fs.StringVar(&n.Domain, "global-nginx-ingress-domain", "certmanager.kubernetes.network", "The domain name that points to the global-nginx-ingress-ip-address. "+
		"All subdomains of this domain must also point to the IP as well.")
}

func (n *NginxRuntimeConfig) Validate() []error {
	var errs []error
	if n.Domain == "" {
		errs = append(errs, fmt.Errorf("--global-nginx-ingress-domain must be specified"))
	}
	if n.IPAddress == "" {
		errs = append(errs, fmt.Errorf("--global-nginx-ingress-ip-address must be specified"))
	}
	return errs
}
