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

package clouddns

import (
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProviderOptions holds the full configuration for the Google Cloud DNS provider.
type DNSProviderOptions struct {
	// Project is the Google Cloud project ID.
	Project string
	// ServiceAccountBytes is the JSON key data for a Google service account.
	// When empty and Ambient is true, Application Default Credentials are used.
	ServiceAccountBytes []byte
	// ServiceAccountFile is the path to a Google service account JSON key file.
	// ServiceAccountBytes takes precedence when both are set.
	ServiceAccountFile string
	// Nameservers is the list of nameservers used for DNS-01 propagation checks.
	Nameservers []string
	// Ambient enables the use of Application Default Credentials when no service
	// account bytes are provided.
	Ambient *bool
	// HostedZoneName is the name of the Cloud DNS managed zone. When empty, the
	// zone is discovered automatically from the FQDN.
	HostedZoneName string
	// Resolver performs DNS lookups during challenge verification.
	Resolver util.Resolver
}

// DNSProviderOption is a functional option for configuring a DNSProvider.
type DNSProviderOption interface {
	ApplyToDNSProviderOptions(*DNSProviderOptions)
}

// Project sets the Google Cloud project ID on DNSProviderOptions.
type Project string

// ApplyToDNSProviderOptions sets the Project field.
func (p Project) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Project = string(p)
}

// ServiceAccountBytes sets the Google service account JSON key data on DNSProviderOptions.
type ServiceAccountBytes []byte

// ApplyToDNSProviderOptions sets the ServiceAccountBytes field.
func (s ServiceAccountBytes) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ServiceAccountBytes = []byte(s)
}

// ServiceAccountFile sets the path to a Google service account JSON key file on DNSProviderOptions.
type ServiceAccountFile string

// ApplyToDNSProviderOptions sets the ServiceAccountFile field.
func (s ServiceAccountFile) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ServiceAccountFile = string(s)
}

// Nameservers sets the DNS nameservers used for propagation checks on DNSProviderOptions.
type Nameservers []string

// ApplyToDNSProviderOptions sets the Nameservers field.
func (n Nameservers) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Nameservers = []string(n)
}

// Ambient enables Application Default Credentials on DNSProviderOptions.
type Ambient bool

// ApplyToDNSProviderOptions sets the Ambient field.
func (a Ambient) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Ambient = new(bool(a))
}

// HostedZoneName sets the Cloud DNS managed zone name on DNSProviderOptions.
type HostedZoneName string

// ApplyToDNSProviderOptions sets the HostedZoneName field.
func (h HostedZoneName) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.HostedZoneName = string(h)
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
