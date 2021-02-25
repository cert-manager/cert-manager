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

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	vaultinternal "github.com/cert-manager/cert-manager/pkg/internal/vault"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	successVaultVerified = "VaultVerified"
	messageVaultVerified = "Vault verified"

	errorVault = "VaultError"

	messageVaultClientInitFailed         = "Failed to initialize Vault client: "
	messageVaultHealthCheckFailed        = "Failed to call Vault health check: "
	messageVaultStatusVerificationFailed = "Vault is not initialized or is sealed"
	messageVaultConfigRequired           = "Vault config cannot be empty"
	messageServerAndPathRequired         = "Vault server and path are required fields"
	messageAuthFieldsRequired            = "Vault tokenSecretRef, appRole, or kubernetes is required"
	messageAuthFieldRequired             = "Multiple auth methods cannot be set on the same Vault issuer"
)

func (v *Vault) Setup(ctx context.Context) error {
	if v.issuer.GetSpec().Vault == nil {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageVaultConfigRequired)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageVaultConfigRequired)
		return nil
	}

	// check if Vault server info is specified.
	if v.issuer.GetSpec().Vault.Server == "" ||
		v.issuer.GetSpec().Vault.Path == "" {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageServerAndPathRequired)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageServerAndPathRequired)
		return nil
	}

	tokenAuth := v.issuer.GetSpec().Vault.Auth.TokenSecretRef
	appRoleAuth := v.issuer.GetSpec().Vault.Auth.AppRole
	kubeAuth := v.issuer.GetSpec().Vault.Auth.Kubernetes

	// check if at least one auth method is specified.
	if tokenAuth == nil && appRoleAuth == nil && kubeAuth == nil {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldsRequired)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldsRequired)
		return nil
	}

	// check only one auth method set
	if (tokenAuth != nil && appRoleAuth != nil) ||
		(tokenAuth != nil && kubeAuth != nil) ||
		(appRoleAuth != nil && kubeAuth != nil) {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	// check if all mandatory Vault Token fields are set.
	if tokenAuth != nil && len(tokenAuth.Name) == 0 {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	// check if all mandatory Vault appRole fields are set.
	if appRoleAuth != nil && (len(appRoleAuth.RoleId) == 0 || len(appRoleAuth.SecretRef.Name) == 0) {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	// check if all mandatory Vault Kubernetes fields are set.
	if kubeAuth != nil && (len(kubeAuth.SecretRef.Name) == 0 || len(kubeAuth.Role) == 0) {
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	client, err := vaultinternal.New(v.resourceNamespace, v.secretsLister, v.issuer)
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, s)
		return err
	}

	health, err := client.Sys().Health()
	if err != nil {
		s := messageVaultHealthCheckFailed + err.Error()
		logf.V(logf.WarnLevel).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, s)
		return err
	}

	if !health.Initialized || health.Sealed {
		logf.V(logf.WarnLevel).Infof("%s: %s: health: %v", v.issuer.GetObjectMeta().Name, messageVaultStatusVerificationFailed, health)
		apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageVaultStatusVerificationFailed)
		return fmt.Errorf(messageVaultStatusVerificationFailed)
	}

	logf.Log.V(logf.DebugLevel).Info(messageVaultVerified)
	apiutil.SetIssuerCondition(v.issuer, v1.IssuerConditionReady, cmmeta.ConditionTrue, successVaultVerified, messageVaultVerified)
	return nil
}
