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

package util

import (
	"crypto/x509"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

var keyUsages = map[cmapi.KeyUsage]x509.KeyUsage{
	cmapi.UsageSigning:            x509.KeyUsageDigitalSignature,
	cmapi.UsageDigitalSignature:   x509.KeyUsageDigitalSignature,
	cmapi.UsageContentCommittment: x509.KeyUsageContentCommitment,
	cmapi.UsageKeyEncipherment:    x509.KeyUsageKeyEncipherment,
	cmapi.UsageKeyAgreement:       x509.KeyUsageKeyAgreement,
	cmapi.UsageDataEncipherment:   x509.KeyUsageDataEncipherment,
	cmapi.UsageCertSign:           x509.KeyUsageCertSign,
	cmapi.UsageCRLSign:            x509.KeyUsageCRLSign,
	cmapi.UsageEncipherOnly:       x509.KeyUsageEncipherOnly,
	cmapi.UsageDecipherOnly:       x509.KeyUsageDecipherOnly,
}

var extKeyUsages = map[cmapi.KeyUsage]x509.ExtKeyUsage{
	cmapi.UsageAny:             x509.ExtKeyUsageAny,
	cmapi.UsageServerAuth:      x509.ExtKeyUsageServerAuth,
	cmapi.UsageClientAuth:      x509.ExtKeyUsageClientAuth,
	cmapi.UsageCodeSigning:     x509.ExtKeyUsageCodeSigning,
	cmapi.UsageEmailProtection: x509.ExtKeyUsageEmailProtection,
	cmapi.UsageSMIME:           x509.ExtKeyUsageEmailProtection,
	cmapi.UsageIPsecEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
	cmapi.UsageIPsecTunnel:     x509.ExtKeyUsageIPSECTunnel,
	cmapi.UsageIPsecUser:       x509.ExtKeyUsageIPSECUser,
	cmapi.UsageTimestamping:    x509.ExtKeyUsageTimeStamping,
	cmapi.UsageOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
	cmapi.UsageMicrosoftSGC:    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	cmapi.UsageNetscapSGC:      x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// KeyUsageType returns the relevant x509.KeyUsage or false if not found
func KeyUsageType(usage cmapi.KeyUsage) (x509.KeyUsage, bool) {
	u, ok := keyUsages[usage]
	return u, ok
}

// ExtKeyUsageType returns the relevant x509.ExtKeyUsage or false if not found
func ExtKeyUsageType(usage cmapi.KeyUsage) (x509.ExtKeyUsage, bool) {
	eu, ok := extKeyUsages[usage]
	return eu, ok
}
