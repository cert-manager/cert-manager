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

package util

import (
	"crypto/x509"
	"math/bits"

	certificatesv1 "k8s.io/api/certificates/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
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
	cmapi.UsageNetscapeSGC:     x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

var keyUsagesKube = map[certificatesv1.KeyUsage]x509.KeyUsage{
	certificatesv1.UsageSigning:           x509.KeyUsageDigitalSignature,
	certificatesv1.UsageDigitalSignature:  x509.KeyUsageDigitalSignature,
	certificatesv1.UsageContentCommitment: x509.KeyUsageContentCommitment,
	certificatesv1.UsageKeyEncipherment:   x509.KeyUsageKeyEncipherment,
	certificatesv1.UsageKeyAgreement:      x509.KeyUsageKeyAgreement,
	certificatesv1.UsageDataEncipherment:  x509.KeyUsageDataEncipherment,
	certificatesv1.UsageCertSign:          x509.KeyUsageCertSign,
	certificatesv1.UsageCRLSign:           x509.KeyUsageCRLSign,
	certificatesv1.UsageEncipherOnly:      x509.KeyUsageEncipherOnly,
	certificatesv1.UsageDecipherOnly:      x509.KeyUsageDecipherOnly,
}

var extKeyUsagesKube = map[certificatesv1.KeyUsage]x509.ExtKeyUsage{
	certificatesv1.UsageAny:             x509.ExtKeyUsageAny,
	certificatesv1.UsageServerAuth:      x509.ExtKeyUsageServerAuth,
	certificatesv1.UsageClientAuth:      x509.ExtKeyUsageClientAuth,
	certificatesv1.UsageCodeSigning:     x509.ExtKeyUsageCodeSigning,
	certificatesv1.UsageEmailProtection: x509.ExtKeyUsageEmailProtection,
	certificatesv1.UsageSMIME:           x509.ExtKeyUsageEmailProtection,
	certificatesv1.UsageIPsecEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
	certificatesv1.UsageIPsecTunnel:     x509.ExtKeyUsageIPSECTunnel,
	certificatesv1.UsageIPsecUser:       x509.ExtKeyUsageIPSECUser,
	certificatesv1.UsageTimestamping:    x509.ExtKeyUsageTimeStamping,
	certificatesv1.UsageOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
	certificatesv1.UsageMicrosoftSGC:    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	certificatesv1.UsageNetscapeSGC:     x509.ExtKeyUsageNetscapeServerGatedCrypto,
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

// TODO
func KeyUsageTypeKube(usage certificatesv1.KeyUsage) (x509.KeyUsage, bool) {
	u, ok := keyUsagesKube[usage]
	return u, ok
}

// TOOD
func ExtKeyUsageTypeKube(usage certificatesv1.KeyUsage) (x509.ExtKeyUsage, bool) {
	eu, ok := extKeyUsagesKube[usage]
	return eu, ok
}

// KeyUsageStrings returns the cmapi.KeyUsage and "unknown" if not found
func KeyUsageStrings(usage x509.KeyUsage) []cmapi.KeyUsage {
	var usageStr []cmapi.KeyUsage

	for i := 0; i < bits.UintSize; i++ {
		if v := usage & (1 << uint(i)); v != 0 {
			usageStr = append(usageStr, keyUsageString(v))
		}
	}

	return usageStr
}

// ExtKeyUsageStrings returns the cmapi.KeyUsage and "unknown" if not found
func ExtKeyUsageStrings(usage []x509.ExtKeyUsage) []cmapi.KeyUsage {
	var usageStr []cmapi.KeyUsage

	for _, u := range usage {
		usageStr = append(usageStr, extKeyUsageString(u))
	}

	return usageStr
}

// keyUsageString returns the cmapi.KeyUsage and "unknown" if not found
func keyUsageString(usage x509.KeyUsage) cmapi.KeyUsage {
	for k, v := range keyUsages {
		if usage == x509.KeyUsageDigitalSignature {
			return cmapi.UsageDigitalSignature // we have KeyUsageDigitalSignature twice in our array, we should be consistent when parsing
		}
		if usage == v {
			return k
		}
	}

	return "unknown"
}

// extKeyUsageString returns the cmapi.ExtKeyUsage and "unknown" if not found
func extKeyUsageString(usage x509.ExtKeyUsage) cmapi.KeyUsage {
	for k, v := range extKeyUsages {
		if usage == v {
			return k
		}
	}

	return "unknown"
}
