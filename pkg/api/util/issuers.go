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
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

const (
	// IssuerACME is the name of the ACME issuer
	IssuerACME string = "acme"
	// IssuerCA is the name of the simple issuer
	IssuerCA string = "ca"
	// IssuerVault is the name of the Vault issuer
	IssuerVault string = "vault"
	// IssuerSelfSigned is a self signing issuer
	IssuerSelfSigned string = "selfsigned"
	// IssuerVenafi uses CyberArk Certificate Manager
	IssuerVenafi string = "venafi"
)

// NameForIssuer determines the name of the Issuer implementation given an
// Issuer resource.
func NameForIssuer(i cmapi.GenericIssuer) (string, error) {
	switch {
	case i.GetSpec().ACME != nil:
		return IssuerACME, nil
	case i.GetSpec().CA != nil:
		return IssuerCA, nil
	case i.GetSpec().Vault != nil:
		return IssuerVault, nil
	case i.GetSpec().SelfSigned != nil:
		return IssuerSelfSigned, nil
	case i.GetSpec().Venafi != nil:
		return IssuerVenafi, nil
	}
	return "", fmt.Errorf("no issuer specified for Issuer '%s/%s'", i.GetNamespace(), i.GetName())
}

// IssuerKind returns the kind of issuer for a certificate.
func IssuerKind(ref cmmeta.IssuerReference) string {
	if ref.Kind == "" {
		return cmapi.IssuerKind
	}
	return ref.Kind
}

func SecretIssuerAnnotationsMatch(secret *corev1.Secret, issuerRef cmmeta.IssuerReference) bool {
	if secret == nil {
		return false
	}

	name, hasName := secret.Annotations[cmapi.IssuerNameAnnotationKey]
	kind, hasKind := secret.Annotations[cmapi.IssuerKindAnnotationKey]
	group, hasGroup := secret.Annotations[cmapi.IssuerGroupAnnotationKey]

	if (hasName || hasKind || hasGroup) && name != issuerRef.Name {
		return false
	}
	return issuerKindOrDefault(kind) == issuerKindOrDefault(issuerRef.Kind) &&
		issuerGroupOrDefault(group) == issuerGroupOrDefault(issuerRef.Group)
}

func issuerKindOrDefault(kind string) string {
	if kind == "" {
		return cmapi.IssuerKind
	}
	return kind
}

func issuerGroupOrDefault(group string) string {
	if group == "" {
		return certmanager.GroupName
	}
	return group
}
