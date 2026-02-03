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

	"k8s.io/klog/v2"

	vaultinternal "github.com/cert-manager/cert-manager/internal/vault"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	successVaultVerified = "VaultVerified"
	messageVaultVerified = "Vault verified"

	errorVault = "VaultError"

	messageVaultClientInitFailed             = "Failed to initialize Vault client"
	messageVaultInitializedAndUnsealedFailed = "Failed to verify Vault is initialized and unsealed"
	messageVaultConfigRequired               = "Vault config cannot be empty"
	messageServerAndPathRequired             = "Vault server and path are required fields"
	messageAuthFieldsRequired                = "Vault tokenSecretRef, appRole, clientCertificate, kubernetes, aws, gcp, or azure is required"
	messageMultipleAuthFieldsSet             = "Multiple auth methods cannot be set on the same Vault issuer"

	messageKubeAuthRoleRequired      = "Vault Kubernetes auth requires a role to be set"
	messageKubeAuthEitherRequired    = "Vault Kubernetes auth requires either secretRef.name or serviceAccountRef.name to be set"
	messageKubeAuthSingleRequired    = "Vault Kubernetes auth cannot be used with both secretRef.name and serviceAccountRef.name"
	messageTokenAuthNameRequired     = "Vault Token auth requires tokenSecretRef.name"
	messageAppRoleAuthFieldsRequired = "Vault AppRole auth requires both roleId and tokenSecretRef.name"
	messageAppRoleAuthKeyRequired    = "Vault AppRole auth requires secretRef.key"
)

// Setup creates a new Vault client and attempts to authenticate with the Vault instance and sets the issuer's conditions to reflect the success of the setup.
func (v *Vault) Setup(ctx context.Context, issuer v1.GenericIssuer) error {
	if issuer.GetSpec().Vault == nil {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageVaultConfigRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageVaultConfigRequired)
		return nil
	}

	// check if Vault server info is specified.
	if issuer.GetSpec().Vault.Server == "" ||
		issuer.GetSpec().Vault.Path == "" {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageServerAndPathRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageServerAndPathRequired)
		return nil
	}

	tokenAuth := issuer.GetSpec().Vault.Auth.TokenSecretRef
	appRoleAuth := issuer.GetSpec().Vault.Auth.AppRole
	clientCertificateAuth := issuer.GetSpec().Vault.Auth.ClientCertificate
	kubeAuth := issuer.GetSpec().Vault.Auth.Kubernetes
	awsAuth := issuer.GetSpec().Vault.Auth.AWS

	// check if at least one auth method is specified.
	if tokenAuth == nil && appRoleAuth == nil && clientCertificateAuth == nil && kubeAuth == nil && awsAuth == nil {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageAuthFieldsRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldsRequired)
		return nil
	}

	// count how many auth methods are set
	authCount := 0
	if tokenAuth != nil {
		authCount++
	}
	if appRoleAuth != nil {
		authCount++
	}
	if clientCertificateAuth != nil {
		authCount++
	}
	if kubeAuth != nil {
		authCount++
	}
	if awsAuth != nil {
		authCount++
	}

	// check only one auth method is set
	if authCount > 1 {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageMultipleAuthFieldsSet, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageMultipleAuthFieldsSet)
		return nil
	}

	// check if all mandatory Vault Token fields are set.
	if tokenAuth != nil && len(tokenAuth.Name) == 0 {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageTokenAuthNameRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageTokenAuthNameRequired)
		return nil
	}

	// check if all mandatory Vault appRole fields are set.
	if appRoleAuth != nil && (len(appRoleAuth.RoleId) == 0 || len(appRoleAuth.SecretRef.Name) == 0) {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageAppRoleAuthFieldsRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAppRoleAuthFieldsRequired)
		return nil
	}
	if appRoleAuth != nil && len(appRoleAuth.SecretRef.Key) == 0 {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageAppRoleAuthKeyRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAppRoleAuthKeyRequired)
		return nil
	}

	// When using the Kubernetes auth, giving a role is mandatory.
	if kubeAuth != nil && len(kubeAuth.Role) == 0 {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageKubeAuthRoleRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageKubeAuthRoleRequired)
		return nil
	}

	// When using the Kubernetes auth, you must either set secretRef or
	// serviceAccountRef.
	if kubeAuth != nil && (kubeAuth.SecretRef.Name == "" && kubeAuth.ServiceAccountRef == nil) {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageKubeAuthEitherRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageKubeAuthEitherRequired)
		return nil
	}

	// When using the Kubernetes auth, you can't use secretRef and
	// serviceAccountRef simultaneously.
	if kubeAuth != nil && (kubeAuth.SecretRef.Name != "" && kubeAuth.ServiceAccountRef != nil) {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageKubeAuthSingleRequired, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageKubeAuthSingleRequired)
		return nil
	}

	client, err := vaultinternal.New(ctx, v.ResourceNamespace(issuer), v.createTokenFn, v.secretsLister, issuer)
	if err != nil {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageVaultClientInitFailed, "err", err, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, fmt.Sprintf("%s: %s", messageVaultClientInitFailed, err.Error()))
		return err
	}

	if err := client.IsVaultInitializedAndUnsealed(); err != nil {
		logf.FromContext(ctx).V(logf.WarnLevel).Info(messageVaultInitializedAndUnsealedFailed, "err", err, "issuer", klog.KObj(issuer))
		apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, fmt.Sprintf("%s: %s", messageVaultInitializedAndUnsealedFailed, err.Error()))
		return err
	}

	logf.FromContext(ctx).V(logf.DebugLevel).Info(messageVaultVerified, "issuer", klog.KObj(issuer))
	apiutil.SetIssuerCondition(issuer, issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionTrue, successVaultVerified, messageVaultVerified)
	return nil
}
