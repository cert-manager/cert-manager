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

	messageVaultClientInitFailed = "Failed to initialize Vault client: "
	messageVaultConfigRequired   = "Vault config cannot be empty"
	messageServerAndPathRequired = "Vault server and path are required fields"
	messageAuthFieldsRequired    = "Vault tokenSecretRef, appRole, clientCertificate, or kubernetes is required"
	messageMultipleAuthFieldsSet = "Multiple auth methods cannot be set on the same Vault issuer"

	messageKubeAuthRoleRequired      = "Vault Kubernetes auth requires a role to be set"
	messageKubeAuthEitherRequired    = "Vault Kubernetes auth requires either secretRef.name or serviceAccountRef.name to be set"
	messageKubeAuthSingleRequired    = "Vault Kubernetes auth cannot be used with both secretRef.name and serviceAccountRef.name"
	messageTokenAuthNameRequired     = "Vault Token auth requires tokenSecretRef.name"
	messageAppRoleAuthFieldsRequired = "Vault AppRole auth requires both roleId and tokenSecretRef.name"
	messageAppRoleAuthKeyRequired    = "Vault AppRole auth requires secretRef.key"
)

// Setup creates a new Vault client and attempts to authenticate with the Vault instance and sets the issuer's conditions to reflect the success of the setup.
func (v *Vault) Setup(ctx context.Context) error {
	if v.issuer.GetSpec().Vault == nil {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageVaultConfigRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageVaultConfigRequired)
		return nil
	}

	// check if Vault server info is specified.
	if v.issuer.GetSpec().Vault.Server == "" ||
		v.issuer.GetSpec().Vault.Path == "" {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageServerAndPathRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageServerAndPathRequired)
		return nil
	}

	tokenAuth := v.issuer.GetSpec().Vault.Auth.TokenSecretRef
	appRoleAuth := v.issuer.GetSpec().Vault.Auth.AppRole
	clientCertificateAuth := v.issuer.GetSpec().Vault.Auth.ClientCertificate
	kubeAuth := v.issuer.GetSpec().Vault.Auth.Kubernetes

	// check if at least one auth method is specified.
	if tokenAuth == nil && appRoleAuth == nil && clientCertificateAuth == nil && kubeAuth == nil {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldsRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldsRequired)
		return nil
	}

	// check only one auth method is set
	if !((tokenAuth != nil && appRoleAuth == nil && clientCertificateAuth == nil && kubeAuth == nil) ||
		(tokenAuth == nil && appRoleAuth != nil && clientCertificateAuth == nil && kubeAuth == nil) ||
		(tokenAuth == nil && appRoleAuth == nil && clientCertificateAuth != nil && kubeAuth == nil) ||
		(tokenAuth == nil && appRoleAuth == nil && clientCertificateAuth == nil && kubeAuth != nil)) {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageMultipleAuthFieldsSet)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageMultipleAuthFieldsSet)
		return nil
	}

	// check if all mandatory Vault Token fields are set.
	if tokenAuth != nil && len(tokenAuth.Name) == 0 {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageTokenAuthNameRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageTokenAuthNameRequired)
		return nil
	}

	// check if all mandatory Vault appRole fields are set.
	if appRoleAuth != nil && (len(appRoleAuth.RoleId) == 0 || len(appRoleAuth.SecretRef.Name) == 0) {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAppRoleAuthFieldsRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAppRoleAuthFieldsRequired)
		return nil
	}
	if appRoleAuth != nil && len(appRoleAuth.SecretRef.Key) == 0 {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAppRoleAuthKeyRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAppRoleAuthKeyRequired)
		return nil
	}

	// When using the Kubernetes auth, giving a role is mandatory.
	if kubeAuth != nil && len(kubeAuth.Role) == 0 {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageKubeAuthRoleRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageKubeAuthRoleRequired)
		return nil
	}

	// When using the Kubernetes auth, you must either set secretRef or
	// serviceAccountRef.
	if kubeAuth != nil && (kubeAuth.SecretRef.Name == "" && kubeAuth.ServiceAccountRef == nil) {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageKubeAuthEitherRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageKubeAuthEitherRequired)
		return nil
	}

	// When using the Kubernetes auth, you can't use secretRef and
	// serviceAccountRef simultaneously.
	if kubeAuth != nil && (kubeAuth.SecretRef.Name != "" && kubeAuth.ServiceAccountRef != nil) {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageKubeAuthSingleRequired)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageKubeAuthSingleRequired)
		return nil
	}

	client, err := vaultinternal.New(ctx, v.resourceNamespace, v.createTokenFn, v.secretsLister, v.issuer)
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, s)
		return err
	}

	if err := client.IsVaultInitializedAndUnsealed(); err != nil {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, err.Error())
		apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, err.Error())
		return err
	}

	logf.Log.V(logf.DebugLevel).Info(messageVaultVerified)
	apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), v1.IssuerConditionReady, cmmeta.ConditionTrue, successVaultVerified, messageVaultVerified)
	return nil
}
