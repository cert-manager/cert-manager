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

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

type SignerIssuerRef struct {
	Namespace, Name string
	Type, Group     string
}

// SignerIssuerRefFromSignerName will return a SignerIssuerRef from a
// CertificateSigningRequests.Spec.SignerName
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

	if len(signerNameSplit) == 1 {
		return SignerIssuerRef{
			Namespace: "",
			Name:      signerNameSplit[0],
			Type:      signerTypeSplit[0],
			Group:     signerTypeSplit[1],
		}, true
	}

	// ClusterIssuers do not have Namespaces
	if signerTypeSplit[0] == "clusterissuers" {
		return SignerIssuerRef{
			Namespace: "",
			Name:      strings.Join(signerNameSplit[0:], "."),
			Type:      signerTypeSplit[0],
			Group:     signerTypeSplit[1],
		}, true
	}

	// Non Cluster Scoped issuers always have Namespaces
	return SignerIssuerRef{
		Namespace: signerNameSplit[0],
		Name:      strings.Join(signerNameSplit[1:], "."),
		Type:      signerTypeSplit[0],
		Group:     signerTypeSplit[1],
	}, true
}

// IssuerKindFromType will return the cert-manager.io Issuer Kind from a
// resource type name.
func IssuerKindFromType(issuerType string) (string, bool) {
	switch issuerType {
	case "issuers":
		return cmapi.IssuerKind, true

	case "clusterissuers":
		return cmapi.ClusterIssuerKind, true

	default:
		return "", false
	}
}
