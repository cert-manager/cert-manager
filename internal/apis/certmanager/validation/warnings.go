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
	// newDefaultPrivateKeyRotationPolicy is raised when the Certificate.Spec.PrivateKey.RotationPolicy is omitted.
	newDefaultPrivateKeyRotationPolicy = "spec.privateKey.rotationPolicy: In cert-manager >= v1.18.0, the default value changed from `Never` to `Always`."
)
