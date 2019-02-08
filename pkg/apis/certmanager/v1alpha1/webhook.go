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

package v1alpha1

type operation string
type result string

const (
	WebhookPresentOperation operation = "present"
	WebhookCleanupOperation operation = "cleanup"

	WebhookResponseResultSuccess result = "success"
	WebhookResponseResultFailure result = "failure"
)

// Represents a serializable payload that is sent to a webhook
type WebhookPayload struct {
	// Define an operation to be executed on DNS records by a webhook
	// Either "present" or "cleanup"
	Operation operation `json:"operation"`

	// FQDN is the fully-qualified name of the record that should have a TXT record set for, e.g. _acme-challenge.example.com
	FQDN string `json:"fqdn"`

	// Domain is the record that should have a TXT record set for, e.g. _acme-challenge
	Domain string `json:"domain"`

	// Value is the value that the TXT record should hold for this domain
	Value string `json:"value"`

	// Metadata is arbitrary additional metadata passed to the plugin from the Issuer resource.
	// This may contain a reference to a secret resource, containing secret data specific to this
	// configuration of the plugin.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Represents a deserializable payload that we get from a webhook
type WebhookResponse struct {
	// Specifies whethere webhook was successful in executing an operation
	// Either "success" or "failure"
	Result result `json:"result"`

	// If result is negative, specifies human-readable reason for the failure
	Reason string `json:"reason,omitempty"`
}
