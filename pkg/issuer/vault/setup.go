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

package vault

import (
	"context"
	"fmt"

	"github.com/cert-manager/issuer-lib/controllers/signer"
	"k8s.io/apimachinery/pkg/types"

	vaultinternal "github.com/cert-manager/cert-manager/internal/vault"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	successVaultVerified = "VaultVerified"
	messageVaultVerified = "Vault verified"
)

// Setup creates a new Vault client and attempts to authenticate with the Vault instance and sets the issuer's conditions to reflect the success of the setup.
func (v *Vault) Setup(ctx context.Context, issuer v1.GenericIssuer) error {
	if issuer.GetSpec().Vault == nil {
		return fmt.Errorf("Vault config cannot be empty")
	}

	// check if Vault server info is specified.
	if issuer.GetSpec().Vault.Server == "" || issuer.GetSpec().Vault.Path == "" {
		return fmt.Errorf("Vault server and path are required fields")
	}

	tokenAuth := issuer.GetSpec().Vault.Auth.TokenSecretRef
	appRoleAuth := issuer.GetSpec().Vault.Auth.AppRole
	clientCertificateAuth := issuer.GetSpec().Vault.Auth.ClientCertificate
	kubeAuth := issuer.GetSpec().Vault.Auth.Kubernetes

	// check if at least one auth method is specified.
	if tokenAuth == nil && appRoleAuth == nil && clientCertificateAuth == nil && kubeAuth == nil {
		return signer.PermanentError{
			Err: fmt.Errorf("Vault tokenSecretRef, appRole, clientCertificate, or kubernetes is required"),
		}
	}

	// check only one auth method is set
	if !((tokenAuth != nil && appRoleAuth == nil && clientCertificateAuth == nil && kubeAuth == nil) ||
		(tokenAuth == nil && appRoleAuth != nil && clientCertificateAuth == nil && kubeAuth == nil) ||
		(tokenAuth == nil && appRoleAuth == nil && clientCertificateAuth != nil && kubeAuth == nil) ||
		(tokenAuth == nil && appRoleAuth == nil && clientCertificateAuth == nil && kubeAuth != nil)) {
		return signer.PermanentError{
			Err: fmt.Errorf("multiple auth methods cannot be set on the same Vault issuer"),
		}
	}

	// check if all mandatory Vault Token fields are set.
	if tokenAuth != nil && len(tokenAuth.Name) == 0 {
		return fmt.Errorf("Vault Token auth requires tokenSecretRef.name")
	}

	// check if all mandatory Vault appRole fields are set.
	if appRoleAuth != nil && (len(appRoleAuth.RoleId) == 0 || len(appRoleAuth.SecretRef.Name) == 0) {
		return fmt.Errorf("Vault AppRole auth requires both roleId and tokenSecretRef.name")
	}
	if appRoleAuth != nil && len(appRoleAuth.SecretRef.Key) == 0 {
		return fmt.Errorf("Vault AppRole auth requires secretRef.key")
	}

	// When using the Kubernetes auth, giving a role is mandatory.
	if kubeAuth != nil && len(kubeAuth.Role) == 0 {
		return fmt.Errorf("Vault Kubernetes auth requires a role to be set")
	}

	// When using the Kubernetes auth, you must either set secretRef or
	// serviceAccountRef.
	if kubeAuth != nil && (kubeAuth.SecretRef.Name == "" && kubeAuth.ServiceAccountRef == nil) {
		return fmt.Errorf("Vault Kubernetes auth requires either secretRef.name or serviceAccountRef.name to be set")
	}

	// When using the Kubernetes auth, you can't use secretRef and
	// serviceAccountRef simultaneously.
	if kubeAuth != nil && (kubeAuth.SecretRef.Name != "" && kubeAuth.ServiceAccountRef != nil) {
		return fmt.Errorf("Vault Kubernetes auth cannot be used with both secretRef.name and serviceAccountRef.name")
	}

	client, err := vaultinternal.New(ctx, types.NamespacedName{
		Name:      issuer.GetName(),
		Namespace: issuer.GetNamespace(),
	}, v.resourceNamespace, v.createTokenFn, v.secretsLister, issuer.GetSpec())
	if err != nil {
		return fmt.Errorf("failed to initialize Vault client: %w", err)
	}

	if err := client.IsVaultInitializedAndUnsealed(); err != nil {
		return fmt.Errorf("failed to verify Vault is initialized and unsealed: %w", err)
	}

	logf.Log.V(logf.DebugLevel).Info(messageVaultVerified)

	return nil
}
