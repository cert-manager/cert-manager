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

package certificates

import (
	"crypto"

	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// This file contains deprecated functions that were moved to the pki package.
// These functions will be removed in a cert-manager release >= v1.13.

// Deprecated: use pki.PrivateKeyMatchesSpec instead.
func PrivateKeyMatchesSpec(pk crypto.PrivateKey, spec cmapi.CertificateSpec) ([]string, error) {
	return pki.PrivateKeyMatchesSpec(pk, spec)
}

// Deprecated: use pki.RequestMatchesSpec instead.
func RequestMatchesSpec(req *cmapi.CertificateRequest, spec cmapi.CertificateSpec) ([]string, error) {
	return pki.RequestMatchesSpec(req, spec)
}

// Deprecated: use pki.SecretDataAltNamesMatchSpec instead.
func SecretDataAltNamesMatchSpec(secret *corev1.Secret, spec cmapi.CertificateSpec) ([]string, error) {
	return pki.SecretDataAltNamesMatchSpec(secret, spec)
}

// Deprecated: use pki.RenewalTimeFunc instead.
type RenewalTimeFunc = pki.RenewalTimeFunc

// Deprecated: use pki.RenewalTime instead.
func RenewalTime(notBefore, notAfter time.Time, renewBeforeOverride *metav1.Duration) *metav1.Time {
	return pki.RenewalTime(notBefore, notAfter, renewBeforeOverride)
}
