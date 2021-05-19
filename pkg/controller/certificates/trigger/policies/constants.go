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

package policies

const (
	// DoesNotExist is a policy violation reason for a scenario where
	// Certificate's spec.secretName secret does not exist.
	DoesNotExist string = "DoesNotExist"
	// MissingData is a policy violation reason for a scenario where
	// Certificate's spec.secretName secret has missing data.
	MissingData string = "MissingData"
	// InvalidKeyPair is a policy violation reason for a scenario where public
	// key of certificate does not match private key.
	InvalidKeyPair string = "InvalidKeyPair"
	// SecretMismatch is a policy violation reason for a scenario where Secret's
	// private key does not match spec.
	SecretMismatch string = "SecretMismatch"
	// IncorrectIssuer is a policy violation reason for a scenario where
	// Certificate has been issued by incorrect Issuer.
	IncorrectIssuer string = "IncorrectIssuer"
	// RequestChanged is a policy violation reason for a scenario where
	// CertificateRequest not valid for Certificate's spec.
	RequestChanged string = "RequestChanged"
	// Renewing is a policy violation reason for a scenario where
	// Certificate's renewal time is now or in past.
	Renewing string = "Renewing"
	// Expired is a policy violation reason for a scenario where Certificate has
	// expired.
	Expired string = "Expired"
)
