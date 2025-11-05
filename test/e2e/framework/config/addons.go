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

// Addons contains global configuration for instances of addons
type Addons struct {
	// Helm describes the global configuration values for helm
	Helm Helm

	// Connection details for the ACME server used during ACME end-to-end
	// tests.
	ACMEServer ACMEServer

	// IngressController contains configuration for the ingress controller
	// being used during ACME HTTP01 tests.
	IngressController IngressController

	// Gateway contains configuration for the Gateway API controller
	// being used during HTTP-01 tests.
	Gateway Gateway

	// Venafi describes global configuration variables for the Venafi tests.
	// This includes credentials for the Venafi TPP server to use during runs.
	Venafi Venafi

	// CertManager contains configuration options for the cert-manager
	// deployment under test.
	CertManager CertManager

	DNS01Webhook DNS01Webhook
}

func (a *Addons) AddFlags(fs *flag.FlagSet) {
	a.Helm.AddFlags(fs)
	a.ACMEServer.AddFlags(fs)
	a.IngressController.AddFlags(fs)
	a.Gateway.AddFlags(fs)
	a.Venafi.AddFlags(fs)
	a.CertManager.AddFlags(fs)
	a.DNS01Webhook.AddFlags(fs)
}

func (a *Addons) Validate() []error {
	var errs []error
	errs = append(errs, a.Helm.Validate()...)
	errs = append(errs, a.ACMEServer.Validate()...)
	errs = append(errs, a.IngressController.Validate()...)
	errs = append(errs, a.Gateway.Validate()...)
	errs = append(errs, a.Venafi.Validate()...)
	errs = append(errs, a.CertManager.Validate()...)
	errs = append(errs, a.DNS01Webhook.Validate()...)
	return errs
}
