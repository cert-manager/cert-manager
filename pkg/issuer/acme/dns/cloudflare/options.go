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

package cloudflare

// DNSProviderOptions holds the full configuration for the Cloudflare DNS provider.
type DNSProviderOptions struct {
	// Email is the Cloudflare account email address. Required when using API key authentication.
	Email string
	// APIKey is the Cloudflare API key. Must be paired with Email.
	APIKey string
	// APIToken is the Cloudflare API token. Used as a standalone credential.
	APIToken string
	// UserAgent is the HTTP User-Agent string sent to the Cloudflare API.
	UserAgent string
}

// DNSProviderOption is a functional option for configuring a DNSProvider.
type DNSProviderOption interface {
	ApplyToDNSProviderOptions(*DNSProviderOptions)
}

// Email sets the Cloudflare account email address on DNSProviderOptions.
type Email string

// ApplyToDNSProviderOptions sets the Email field.
func (e Email) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Email = string(e)
}

// APIKey sets the Cloudflare API key on DNSProviderOptions.
type APIKey string

// ApplyToDNSProviderOptions sets the APIKey field.
func (a APIKey) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.APIKey = string(a)
}

// APIToken sets the Cloudflare API token on DNSProviderOptions.
type APIToken string

// ApplyToDNSProviderOptions sets the APIToken field.
func (a APIToken) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.APIToken = string(a)
}

// UserAgent sets the HTTP User-Agent string on DNSProviderOptions.
type UserAgent string

// ApplyToDNSProviderOptions sets the UserAgent field.
func (u UserAgent) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.UserAgent = string(u)
}
