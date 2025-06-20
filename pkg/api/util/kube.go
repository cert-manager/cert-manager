/*
Copyright 2021 The cert-manager Authors.

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
)

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

// KeyUsageTypeKube returns the relevant x509.KeyUsage or false if not found
func KeyUsageTypeKube(usage certificatesv1.KeyUsage) (x509.KeyUsage, bool) {
	u, ok := keyUsagesKube[usage]
	return u, ok
}

// ExtKeyUsageTypeKube returns the relevant x509.KeyUsage or false if not found
func ExtKeyUsageTypeKube(usage certificatesv1.KeyUsage) (x509.ExtKeyUsage, bool) {
	eu, ok := extKeyUsagesKube[usage]
	return eu, ok
}

// KubeKeyUsageStrings returns the certificatesv1.KeyUsage and "unknown" if not
// found
func KubeKeyUsageStrings(usage x509.KeyUsage) []certificatesv1.KeyUsage {
	var usageStr []certificatesv1.KeyUsage

	for i := range bits.UintSize {
		if v := usage & (1 << i); v != 0 {
			usageStr = append(usageStr, kubeKeyUsageString(v))
		}
	}

	return usageStr
}

// KubeExtKeyUsageStrings returns the certificatesv1.KeyUsage and "unknown" if not found
func KubeExtKeyUsageStrings(usage []x509.ExtKeyUsage) []certificatesv1.KeyUsage {
	var usageStr []certificatesv1.KeyUsage

	for _, u := range usage {
		usageStr = append(usageStr, kubeExtKeyUsageString(u))
	}

	return usageStr
}

// kubeKeyUsageString returns the cmapi.KeyUsage and "unknown" if not found
func kubeKeyUsageString(usage x509.KeyUsage) certificatesv1.KeyUsage {
	if usage == x509.KeyUsageDigitalSignature {
		return certificatesv1.UsageDigitalSignature // we have two keys that map to KeyUsageDigitalSignature in our map, we should be consistent when parsing
	}

	for k, v := range keyUsagesKube {
		if usage == v {
			return k
		}
	}

	return "unknown"
}

// kubeExtKeyUsageString returns the cmapi.ExtKeyUsage and "unknown" if not found
func kubeExtKeyUsageString(usage x509.ExtKeyUsage) certificatesv1.KeyUsage {
	if usage == x509.ExtKeyUsageEmailProtection {
		return certificatesv1.UsageEmailProtection // we have two keys that map to ExtKeyUsageEmailProtection in our map, we should be consistent when parsing
	}

	for k, v := range extKeyUsagesKube {
		if usage == v {
			return k
		}
	}

	return "unknown"
}
