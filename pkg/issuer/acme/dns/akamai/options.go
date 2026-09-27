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

package akamai

import (
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProviderOptions holds the full configuration for the Akamai DNS provider.
type DNSProviderOptions struct {
	// ServiceConsumerDomain is the Akamai EdgeGrid host (e.g. "akab-xxx.luna.akamaiapis.net").
	ServiceConsumerDomain string
	// ClientToken is the Akamai EdgeGrid client token.
	ClientToken string
	// ClientSecret is the Akamai EdgeGrid client secret.
	ClientSecret string
	// AccessToken is the Akamai EdgeGrid access token.
	AccessToken string
	// Nameservers is the list of nameservers used for DNS-01 propagation checks.
	Nameservers []string
	// Resolver performs DNS lookups during challenge verification.
	Resolver util.Resolver
}

// DNSProviderOption is a functional option for configuring a DNSProvider.
type DNSProviderOption interface {
	ApplyToDNSProviderOptions(*DNSProviderOptions)
}

// ServiceConsumerDomain sets the Akamai EdgeGrid host on DNSProviderOptions.
type ServiceConsumerDomain string

// ApplyToDNSProviderOptions sets the ServiceConsumerDomain field.
func (s ServiceConsumerDomain) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ServiceConsumerDomain = string(s)
}

// ClientToken sets the Akamai EdgeGrid client token on DNSProviderOptions.
type ClientToken string

// ApplyToDNSProviderOptions sets the ClientToken field.
func (c ClientToken) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ClientToken = string(c)
}

// ClientSecret sets the Akamai EdgeGrid client secret on DNSProviderOptions.
type ClientSecret string

// ApplyToDNSProviderOptions sets the ClientSecret field.
func (c ClientSecret) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ClientSecret = string(c)
}

// AccessToken sets the Akamai EdgeGrid access token on DNSProviderOptions.
type AccessToken string

// ApplyToDNSProviderOptions sets the AccessToken field.
func (a AccessToken) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.AccessToken = string(a)
}

// Nameservers sets the DNS nameservers used for propagation checks on DNSProviderOptions.
type Nameservers []string

// ApplyToDNSProviderOptions sets the Nameservers field.
func (n Nameservers) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Nameservers = []string(n)
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
