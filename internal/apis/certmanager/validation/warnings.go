/*
Copyright 2020 The cert-manager Authors.

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

package validation

// Warning values thrown by validating webhook
// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
const (
	// deprecatedACMEEABKeyAlgorithmField is raised when the deprecated keyAlgorithm field for an ACME issuer's external account binding (EAB) is set.
	deprecatedACMEEABKeyAlgorithmField = "ACME issuer spec field 'externalAccount.keyAlgorithm' is deprecated. The value of this field will be ignored."

	// weakRFC2136TSIGAlgorithm is raised when an ACME issuer's RFC2136
	// solver explicitly sets a weak TSIG algorithm. The algorithm is still
	// accepted and supported by the v1 API. The first argument is the field
	// path and the second is the value as written by the user.
	weakRFC2136TSIGAlgorithm = "ACME issuer solver field %q uses the weak TSIG algorithm %q. RFC 8945 says HMAC-MD5 must not be used and HMAC-SHA1 is not recommended. Use HMACSHA256 or HMACSHA512."
)
