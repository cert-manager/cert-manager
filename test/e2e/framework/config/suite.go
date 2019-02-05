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
	"os"
)

type Suite struct {
	ACME ACME
}

type ACME struct {
	Cloudflare Cloudflare
}

type Cloudflare struct {
	Domain string
	Email  string
	APIKey string
}

func (f *Suite) AddFlags(fs *flag.FlagSet) {
	f.ACME.AddFlags(fs)
}

func (c *Suite) Validate() []error {
	var errs []error
	errs = append(errs, c.ACME.Validate()...)
	return errs
}

func (c *ACME) AddFlags(fs *flag.FlagSet) {
	c.Cloudflare.AddFlags(fs)
}

func (c *ACME) Validate() []error {
	return nil
}

func (c *Cloudflare) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.Domain, "suite.acme-cloudflare-domain", os.Getenv("CLOUDFLARE_E2E_DOMAIN"), ""+
		"The cloudflare API domain name. If not specified, DNS tests will be skipped")
	fs.StringVar(&c.Email, "suite.acme-cloudflare-email", os.Getenv("CLOUDFLARE_E2E_EMAIL"), ""+
		"The cloudflare API email address. If not specified, DNS tests will be skipped")
	fs.StringVar(&c.APIKey, "suite.acme-cloudflare-api-key", os.Getenv("CLOUDFLARE_E2E_API_TOKEN"), ""+
		"The cloudflare API key. If not specified, DNS tests will be skipped")
}
