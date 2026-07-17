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

package route53

import (
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProviderOptions holds the full configuration for the AWS Route 53 DNS provider.
type DNSProviderOptions struct {
	// AccessKeyID is the AWS access key ID.
	// When empty and Ambient is true, credentials are sourced from the environment.
	AccessKeyID string
	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string
	// Ambient enables the use of ambient AWS credentials (instance profile,
	// environment variables, etc.) when no explicit credentials are provided.
	Ambient *bool
	// Region is the AWS region for the Route 53 API. When empty, the region is
	// determined from the environment.
	Region string
	// Role is the ARN of the IAM role to assume when making Route 53 API calls.
	Role string
	// WebIdentityToken is the web identity token used with Role for OIDC-based
	// role assumption.
	WebIdentityToken string
	// HostedZoneID restricts zone discovery to this specific Route 53 hosted zone ID.
	// When empty, the zone is discovered automatically from the FQDN.
	HostedZoneID string
	// Nameservers is the list of nameservers used for DNS-01 propagation checks.
	Nameservers []string
	// UserAgent is the HTTP User-Agent string appended to AWS API requests.
	UserAgent string
	// Resolver performs DNS lookups during challenge verification.
	Resolver util.Resolver
}

// DNSProviderOption is a functional option for configuring a DNSProvider.
type DNSProviderOption interface {
	ApplyToDNSProviderOptions(*DNSProviderOptions)
}

// AccessKeyID sets the AWS access key ID on DNSProviderOptions.
type AccessKeyID string

// ApplyToDNSProviderOptions sets the AccessKeyID field.
func (a AccessKeyID) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.AccessKeyID = string(a)
}

// SecretAccessKey sets the AWS secret access key on DNSProviderOptions.
type SecretAccessKey string

// ApplyToDNSProviderOptions sets the SecretAccessKey field.
func (s SecretAccessKey) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.SecretAccessKey = string(s)
}

// Ambient enables ambient AWS credential lookup on DNSProviderOptions.
type Ambient bool

// ApplyToDNSProviderOptions sets the Ambient field.
func (a Ambient) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Ambient = new(bool(a))
}

// Region sets the AWS region on DNSProviderOptions.
type Region string

// ApplyToDNSProviderOptions sets the Region field.
func (r Region) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Region = string(r)
}

// Role sets the IAM role ARN to assume on DNSProviderOptions.
type Role string

// ApplyToDNSProviderOptions sets the Role field.
func (r Role) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Role = string(r)
}

// WebIdentityToken sets the web identity token on DNSProviderOptions.
type WebIdentityToken string

// ApplyToDNSProviderOptions sets the WebIdentityToken field.
func (w WebIdentityToken) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.WebIdentityToken = string(w)
}

// HostedZoneID sets the Route 53 hosted zone ID on DNSProviderOptions.
type HostedZoneID string

// ApplyToDNSProviderOptions sets the HostedZoneID field.
func (h HostedZoneID) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.HostedZoneID = string(h)
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

// Resolver returns a WithResolver option that sets the Resolver field on DNSProviderOptions.
func Resolver(r util.Resolver) WithResolver {
	return WithResolver{Resolver: r}
}
