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

import "flag"

// Addons contains global configuration for instances of addons
type Addons struct {
	// Tiller describes the global configuration values for the tiller addon
	Tiller Tiller

	// Helm describes the global configuration values for helm
	Helm Helm

	// Pebble describes the global configuration values for the pebble addon
	Pebble Pebble

	// Nginx describes global configuration variables for the nginx addon.
	// Because we currently can only run one instance of nginx per cluster due
	// to the way we provision DNS, this structure currently also describes
	// the runtime configuration for a global shared Nginx instance as well.
	Nginx Nginx

	// Venafi describes global configuration variables for the Venafi tests.
	// This includes credentials for the Venafi TPP server to use during runs.
	Venafi Venafi
}

func (a *Addons) AddFlags(fs *flag.FlagSet) {
	a.Tiller.AddFlags(fs)
	a.Helm.AddFlags(fs)
	a.Pebble.AddFlags(fs)
	a.Nginx.AddFlags(fs)
	a.Venafi.AddFlags(fs)
}

func (c *Addons) Validate() []error {
	var errs []error
	errs = append(errs, c.Tiller.Validate()...)
	errs = append(errs, c.Helm.Validate()...)
	errs = append(errs, c.Pebble.Validate()...)
	errs = append(errs, c.Nginx.Validate()...)
	errs = append(errs, c.Venafi.Validate()...)
	return errs
}
