/*
Copyright 2026 The cert-manager Authors.

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

package digitalocean

import (
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProviderOptions holds the full configuration for the DigitalOcean DNS provider.
type DNSProviderOptions struct {
	// Token is the DigitalOcean API access token.
	Token string
	// Nameservers is the list of nameservers used for DNS-01 propagation checks.
	Nameservers []string
	// UserAgent is the HTTP User-Agent string sent to the DigitalOcean API.
	UserAgent string
	// Resolver performs DNS lookups during challenge verification.
	Resolver util.Resolver
}

// DNSProviderOption is a functional option for configuring a DNSProvider.
type DNSProviderOption interface {
	ApplyToDNSProviderOptions(*DNSProviderOptions)
}

// Token sets the DigitalOcean API access token on DNSProviderOptions.
type Token string

// ApplyToDNSProviderOptions sets the Token field.
func (t Token) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Token = string(t)
}

// Nameservers sets the DNS nameservers used for propagation checks on DNSProviderOptions.
type Nameservers []string

// ApplyToDNSProviderOptions sets the Nameservers field.
func (n Nameservers) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Nameservers = []string(n)
}

// UserAgent sets the HTTP User-Agent string on DNSProviderOptions.
type UserAgent string

// ApplyToDNSProviderOptions sets the UserAgent field.
func (u UserAgent) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.UserAgent = string(u)
}

// WithResolver sets the Resolver used for DNS lookups on DNSProviderOptions.
type WithResolver struct{ util.Resolver }

// ApplyToDNSProviderOptions sets the Resolver field.
func (r WithResolver) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Resolver = r.Resolver
}

// Resolver sets the Resolver used for DNS lookups on DNSProviderOptions.
func Resolver(r util.Resolver) WithResolver {
	return WithResolver{Resolver: r}
}
