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

package azuredns

import (
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

// DNSProviderOptions holds the full configuration for the Azure DNS provider.
type DNSProviderOptions struct {
	// Environment is the Azure cloud environment name (e.g. "AzurePublicCloud").
	// Defaults to AzurePublicCloud when empty.
	Environment string
	// ClientID is the Azure service principal client ID.
	// When empty, ambient credentials (workload identity or MSI) are used.
	ClientID string
	// ClientSecret is the Azure service principal client secret.
	ClientSecret string
	// SubscriptionID is the Azure subscription ID.
	SubscriptionID string
	// TenantID is the Azure Active Directory tenant ID.
	TenantID string
	// ResourceGroupName is the Azure resource group containing the DNS zone.
	ResourceGroupName string
	// ZoneName is the name of the DNS zone. When empty, the zone is discovered
	// automatically from the FQDN.
	ZoneName string
	// Nameservers is the list of nameservers used for DNS-01 propagation checks.
	Nameservers []string
	// Ambient enables the use of ambient credentials (Azure Workload Identity or MSI).
	Ambient *bool
	// ManagedIdentity configures an Azure Managed Identity or Workload Identity
	// to use when Ambient is true.
	ManagedIdentity *cmacme.AzureManagedIdentity
	// ZoneType selects between public and private Azure DNS zones.
	ZoneType cmacme.AzureZoneType
	// Resolver performs DNS lookups during challenge verification.
	Resolver util.Resolver
}

// DNSProviderOption is a functional option for configuring a DNSProvider.
type DNSProviderOption interface {
	ApplyToDNSProviderOptions(*DNSProviderOptions)
}

// Environment sets the Azure cloud environment name on DNSProviderOptions.
type Environment string

// ApplyToDNSProviderOptions sets the Environment field.
func (e Environment) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Environment = string(e)
}

// ClientID sets the Azure service principal client ID on DNSProviderOptions.
type ClientID string

// ApplyToDNSProviderOptions sets the ClientID field.
func (c ClientID) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ClientID = string(c)
}

// ClientSecret sets the Azure service principal client secret on DNSProviderOptions.
type ClientSecret string

// ApplyToDNSProviderOptions sets the ClientSecret field.
func (c ClientSecret) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ClientSecret = string(c)
}

// SubscriptionID sets the Azure subscription ID on DNSProviderOptions.
type SubscriptionID string

// ApplyToDNSProviderOptions sets the SubscriptionID field.
func (s SubscriptionID) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.SubscriptionID = string(s)
}

// TenantID sets the Azure Active Directory tenant ID on DNSProviderOptions.
type TenantID string

// ApplyToDNSProviderOptions sets the TenantID field.
func (t TenantID) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.TenantID = string(t)
}

// ResourceGroupName sets the Azure resource group name on DNSProviderOptions.
type ResourceGroupName string

// ApplyToDNSProviderOptions sets the ResourceGroupName field.
func (r ResourceGroupName) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ResourceGroupName = string(r)
}

// ZoneName sets the DNS zone name on DNSProviderOptions.
type ZoneName string

// ApplyToDNSProviderOptions sets the ZoneName field.
func (z ZoneName) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ZoneName = string(z)
}

// Nameservers sets the DNS nameservers used for propagation checks on DNSProviderOptions.
type Nameservers []string

// ApplyToDNSProviderOptions sets the Nameservers field.
func (n Nameservers) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Nameservers = []string(n)
}

// Ambient enables ambient credential lookup (Workload Identity or MSI) on DNSProviderOptions.
type Ambient bool

// ApplyToDNSProviderOptions sets the Ambient field.
func (a Ambient) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Ambient = new(bool(a))
}

// ZoneType sets the Azure DNS zone type (public or private) on DNSProviderOptions.
type ZoneType cmacme.AzureZoneType

// ApplyToDNSProviderOptions sets the ZoneType field.
func (z ZoneType) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ZoneType = cmacme.AzureZoneType(z)
}

// WithManagedIdentity sets the Azure Managed Identity configuration on DNSProviderOptions.
type WithManagedIdentity struct{ *cmacme.AzureManagedIdentity }

// ApplyToDNSProviderOptions sets the ManagedIdentity field.
func (m WithManagedIdentity) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.ManagedIdentity = m.AzureManagedIdentity
}

// ManagedIdentity sets the identity used for DNS lookups on DNSProviderOptions.
func ManagedIdentity(a *cmacme.AzureManagedIdentity) WithManagedIdentity {
	return WithManagedIdentity{AzureManagedIdentity: a}
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
