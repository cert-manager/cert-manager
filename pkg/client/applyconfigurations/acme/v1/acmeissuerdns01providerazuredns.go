/*
Copyright The cert-manager Authors.

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

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration represents an declarative configuration of the ACMEIssuerDNS01ProviderAzureDNS type for use
// with apply.
type ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration struct {
	ClientID          *string                                 `json:"clientID,omitempty"`
	ClientSecret      *v1.SecretKeySelector                   `json:"clientSecretSecretRef,omitempty"`
	SubscriptionID    *string                                 `json:"subscriptionID,omitempty"`
	TenantID          *string                                 `json:"tenantID,omitempty"`
	ResourceGroupName *string                                 `json:"resourceGroupName,omitempty"`
	HostedZoneName    *string                                 `json:"hostedZoneName,omitempty"`
	Environment       *acmev1.AzureDNSEnvironment             `json:"environment,omitempty"`
	ManagedIdentity   *AzureManagedIdentityApplyConfiguration `json:"managedIdentity,omitempty"`
}

// ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration constructs an declarative configuration of the ACMEIssuerDNS01ProviderAzureDNS type for use with
// apply.
func ACMEIssuerDNS01ProviderAzureDNS() *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	return &ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration{}
}

// WithClientID sets the ClientID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClientID field is set to the value of the last call.
func (b *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration) WithClientID(value string) *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	b.ClientID = &value
	return b
}

// WithClientSecret sets the ClientSecret field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClientSecret field is set to the value of the last call.
func (b *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration) WithClientSecret(value v1.SecretKeySelector) *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	b.ClientSecret = &value
	return b
}

// WithSubscriptionID sets the SubscriptionID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SubscriptionID field is set to the value of the last call.
func (b *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration) WithSubscriptionID(value string) *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	b.SubscriptionID = &value
	return b
}

// WithTenantID sets the TenantID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TenantID field is set to the value of the last call.
func (b *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration) WithTenantID(value string) *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	b.TenantID = &value
	return b
}

// WithResourceGroupName sets the ResourceGroupName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ResourceGroupName field is set to the value of the last call.
func (b *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration) WithResourceGroupName(value string) *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	b.ResourceGroupName = &value
	return b
}

// WithHostedZoneName sets the HostedZoneName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the HostedZoneName field is set to the value of the last call.
func (b *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration) WithHostedZoneName(value string) *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	b.HostedZoneName = &value
	return b
}

// WithEnvironment sets the Environment field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Environment field is set to the value of the last call.
func (b *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration) WithEnvironment(value acmev1.AzureDNSEnvironment) *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	b.Environment = &value
	return b
}

// WithManagedIdentity sets the ManagedIdentity field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ManagedIdentity field is set to the value of the last call.
func (b *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration) WithManagedIdentity(value *AzureManagedIdentityApplyConfiguration) *ACMEIssuerDNS01ProviderAzureDNSApplyConfiguration {
	b.ManagedIdentity = value
	return b
}
