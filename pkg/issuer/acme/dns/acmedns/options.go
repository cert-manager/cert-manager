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

package acmedns

// DNSProviderOptions holds the full configuration for the ACME DNS provider.
type DNSProviderOptions struct {
	// Host is the base URL of the acme-dns instance.
	Host string
	// AccountJSON contains the JSON-encoded account credentials returned by the
	// acme-dns registration endpoint.
	AccountJSON []byte
}

// DNSProviderOption is a functional option for configuring a DNSProvider.
type DNSProviderOption interface {
	ApplyToDNSProviderOptions(*DNSProviderOptions)
}

// Host sets the base URL of the acme-dns instance on DNSProviderOptions.
type Host string

// ApplyToDNSProviderOptions sets the Host field.
func (h Host) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.Host = string(h)
}

// AccountJSON sets the JSON-encoded acme-dns account credentials on DNSProviderOptions.
type AccountJSON []byte

// ApplyToDNSProviderOptions sets the AccountJSON field.
func (a AccountJSON) ApplyToDNSProviderOptions(o *DNSProviderOptions) {
	o.AccountJSON = a
}
