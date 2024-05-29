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

package gen

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type IssuerModifier func(v1.GenericIssuer)

func ClusterIssuer(name string, mods ...IssuerModifier) *v1.ClusterIssuer {
	c := &v1.ClusterIssuer{
		ObjectMeta: ObjectMeta(name),
	}
	c.ObjectMeta.Namespace = ""
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func ClusterIssuerFrom(iss *v1.ClusterIssuer, mods ...IssuerModifier) *v1.ClusterIssuer {
	for _, mod := range mods {
		mod(iss)
	}
	return iss
}

// ClusterIssuerWithRandomName returns a ClusterIssuer named 'prefix<random-string>'
// with the specified modifications.
func ClusterIssuerWithRandomName(prefix string, mods ...IssuerModifier) *v1.ClusterIssuer {
	iss := &v1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: prefix,
		},
	}
	for _, mod := range mods {
		mod(iss)
	}
	return iss
}

func Issuer(name string, mods ...IssuerModifier) *v1.Issuer {
	c := &v1.Issuer{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func IssuerFrom(iss *v1.Issuer, mods ...IssuerModifier) *v1.Issuer {
	iss = iss.DeepCopy()
	for _, mod := range mods {
		mod(iss)
	}
	return iss
}

// IssuerWithRandomName returns a new Issuer named prefix<random-string>
// with the provided modifications.
func IssuerWithRandomName(prefix string, mods ...IssuerModifier) *v1.Issuer {
	iss := &v1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: prefix,
		},
	}
	for _, mod := range mods {
		mod(iss)
	}
	return iss
}

func SetIssuerACME(a cmacme.ACMEIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().ACME = &a
	}
}

func SetIssuerACMEPreferredChain(chain string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.PreferredChain = chain
	}
}

func SetIssuerACMEURL(url string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.Server = url
	}
}

func SetIssuerACMEEmail(email string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.Email = email
	}
}
func SetIssuerACMEPrivKeyRef(privateKeyName string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.PrivateKey = cmmeta.SecretKeySelector{
			LocalObjectReference: cmmeta.LocalObjectReference{
				Name: privateKeyName,
			},
		}
	}
}
func SetIssuerACMESolvers(solvers []cmacme.ACMEChallengeSolver) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.Solvers = solvers
	}
}

func SetIssuerACMEDuration(enabled bool) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.EnableDurationFeature = enabled
	}
}

func SetIssuerACMESkipTLSVerify(shouldSkip bool) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.SkipTLSVerify = shouldSkip
	}
}

func SetIssuerACMEDisableAccountKeyGeneration(disabled bool) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.DisableAccountKeyGeneration = disabled
	}
}

func SetIssuerACMEEAB(keyID, secretName string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.ExternalAccountBinding = &cmacme.ACMEExternalAccountBinding{
			KeyID: keyID,
			Key: cmmeta.SecretKeySelector{
				Key: "key",
				LocalObjectReference: cmmeta.LocalObjectReference{
					Name: secretName,
				},
			},
		}
	}
}

// SetIssuerACMEEABWithKeyAlgorithm returns an ACME Issuer modifier that sets
// ACME External Account Binding with the legacy keyAlgorithm field set.
func SetIssuerACMEEABWithKeyAlgorithm(keyID, secretName string, keyAlgorithm cmacme.HMACKeyAlgorithm) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.ACME == nil {
			spec.ACME = &cmacme.ACMEIssuer{}
		}
		spec.ACME.ExternalAccountBinding = &cmacme.ACMEExternalAccountBinding{
			KeyID:        keyID,
			KeyAlgorithm: keyAlgorithm,
			Key: cmmeta.SecretKeySelector{
				Key: "key",
				LocalObjectReference: cmmeta.LocalObjectReference{
					Name: secretName,
				},
			},
		}
	}
}

func SetIssuerACMEAccountURL(url string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		status := iss.GetStatus()
		if status.ACME == nil {
			status.ACME = &cmacme.ACMEIssuerStatus{}
		}
		status.ACME.URI = url
	}
}

func SetIssuerACMELastRegisteredEmail(email string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		status := iss.GetStatus()
		if status.ACME == nil {
			status.ACME = &cmacme.ACMEIssuerStatus{}
		}
		status.ACME.LastRegisteredEmail = email
	}
}

func SetIssuerACMELastPrivateKeyHash(privateKeyHash string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		status := iss.GetStatus()
		if status.ACME == nil {
			status.ACME = &cmacme.ACMEIssuerStatus{}
		}
		status.ACME.LastPrivateKeyHash = privateKeyHash
	}
}

func SetIssuerCA(a v1.CAIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().CA = &a
	}
}

func SetIssuerCASecretName(secretName string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.CA == nil {
			spec.CA = &v1.CAIssuer{}
		}
		spec.CA.SecretName = secretName
	}
}

func SetIssuerVault(v v1.VaultIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().Vault = &v
	}
}
func SetIssuerVaultURL(url string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.Server = url
	}
}

func SetIssuerVaultPath(path string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.Path = path
	}
}

func SetIssuerVaultCABundle(caBundle []byte) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.CABundle = caBundle
	}
}

func SetIssuerVaultCABundleSecretRef(name, namespace, key string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.CABundleSecretRef = &cmmeta.SecretKeySelector{
			LocalObjectReference: cmmeta.LocalObjectReference{
				Name: name,
			},
			Key: key,
		}
	}
}

func SetIssuerVaultClientCertSecretRef(vaultClientCertificateSecretName, key string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.ClientCertSecretRef = &cmmeta.SecretKeySelector{
			LocalObjectReference: cmmeta.LocalObjectReference{
				Name: vaultClientCertificateSecretName,
			},
			Key: key,
		}
	}
}

func SetIssuerVaultClientKeySecretRef(vaultClientCertificateSecretName, key string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.ClientKeySecretRef = &cmmeta.SecretKeySelector{
			LocalObjectReference: cmmeta.LocalObjectReference{
				Name: vaultClientCertificateSecretName,
			},
			Key: key,
		}
	}
}

func SetIssuerVaultTokenAuth(keyName, tokenName string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.Auth.TokenSecretRef = &cmmeta.SecretKeySelector{
			Key: keyName,
			LocalObjectReference: cmmeta.LocalObjectReference{
				Name: tokenName,
			},
		}
	}
}
func SetIssuerVaultAppRoleAuth(keyName, approleName, roleId, path string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.Auth.AppRole = &v1.VaultAppRole{
			Path:   path,
			RoleId: roleId,
			SecretRef: cmmeta.SecretKeySelector{
				Key: keyName,
				LocalObjectReference: cmmeta.LocalObjectReference{
					Name: approleName,
				},
			},
		}
	}
}

func SetIssuerVaultKubernetesAuthSecret(secretKey, secretName, vaultRole, vaultPath string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.Auth.Kubernetes = &v1.VaultKubernetesAuth{
			Path: vaultPath,
			SecretRef: cmmeta.SecretKeySelector{
				Key: secretKey,
				LocalObjectReference: cmmeta.LocalObjectReference{
					Name: secretName,
				},
			},
			Role: vaultRole,
		}

	}
}

func SetIssuerVaultKubernetesAuthServiceAccount(serviceAccount, role, path string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		spec := iss.GetSpec()
		if spec.Vault == nil {
			spec.Vault = &v1.VaultIssuer{}
		}
		spec.Vault.Auth.Kubernetes = &v1.VaultKubernetesAuth{
			Path: path,
			Role: role,
			ServiceAccountRef: &v1.ServiceAccountRef{
				Name: serviceAccount,
			},
		}

	}
}

func SetIssuerSelfSigned(a v1.SelfSignedIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().SelfSigned = &a
	}
}

func SetIssuerVenafi(a v1.VenafiIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().Venafi = &a
	}
}

func AddIssuerCondition(c v1.IssuerCondition) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetStatus().Conditions = append(iss.GetStatus().Conditions, c)
	}
}

func SetIssuerNamespace(namespace string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetObjectMeta().Namespace = namespace
	}
}
