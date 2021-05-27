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
	"strings"
)

type SignerIssuerRef struct {
	Namespace, Name string
	Type, Group     string
}

// SignerIssuerRefFromSignerName will return a SignerIssuerRef from a
// CertificateSigningRequests.SignerName
func SignerIssuerRefFromSignerName(name string) (SignerIssuerRef, bool) {
	split := strings.Split(name, "/")
	if len(split) != 2 {
		return SignerIssuerRef{}, false
	}

	signerTypeSplit := strings.SplitN(split[0], ".", 2)
	signerNameSplit := strings.Split(split[1], ".")

	if len(signerTypeSplit) < 2 || signerNameSplit[0] == "" {
		return SignerIssuerRef{}, false
	}

	switch len(signerNameSplit) {
	case 1:
		return SignerIssuerRef{
			Namespace: "",
			Name:      signerNameSplit[0],
			Type:      signerTypeSplit[0],
			Group:     signerTypeSplit[1],
		}, true

	default:
		return SignerIssuerRef{
			Namespace: signerNameSplit[0],
			Name:      strings.Join(signerNameSplit[1:], "."),
			Type:      signerTypeSplit[0],
			Group:     signerTypeSplit[1],
		}, true
	}
}
