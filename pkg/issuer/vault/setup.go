/*
Copyright 2019 The Jetstack cert-manager contributors.

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

	"k8s.io/klog"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
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
	messsageAuthFieldsRequired           = "Vault tokenSecretRef or appRole is required"
	messageAuthFieldRequired             = "Vault tokenSecretRef and appRole cannot be set on the same issuer"
)

func (v *Vault) Setup(ctx context.Context) error {
	if v.issuer.GetSpec().Vault == nil {
		klog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageVaultConfigRequired)
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageVaultConfigRequired)
		return nil
	}

	// check if Vault server info is specified.
	if v.issuer.GetSpec().Vault.Server == "" ||
		v.issuer.GetSpec().Vault.Path == "" {
		klog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageServerAndPathRequired)
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageServerAndPathRequired)
		return nil
	}

	// check if at least one auth method is specified.
	if v.issuer.GetSpec().Vault.Auth.TokenSecretRef.Name == "" &&
		v.issuer.GetSpec().Vault.Auth.AppRole.RoleId == "" &&
		v.issuer.GetSpec().Vault.Auth.AppRole.SecretRef.Name == "" {
		klog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messsageAuthFieldsRequired)
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messsageAuthFieldsRequired)
		return nil
	}

	// check if only token auth method is set.
	if v.issuer.GetSpec().Vault.Auth.TokenSecretRef.Name != "" &&
		(v.issuer.GetSpec().Vault.Auth.AppRole.RoleId != "" ||
			v.issuer.GetSpec().Vault.Auth.AppRole.SecretRef.Name != "") {
		klog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	// check if all mandatory Vault appRole fields are set.
	if v.issuer.GetSpec().Vault.Auth.TokenSecretRef.Name == "" &&
		(v.issuer.GetSpec().Vault.Auth.AppRole.RoleId == "" ||
			v.issuer.GetSpec().Vault.Auth.AppRole.SecretRef.Name == "") {
		klog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	client, err := v.initVaultClient()
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		klog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, s)
		return err
	}

	health, err := client.Sys().Health()
	if err != nil {
		s := messageVaultHealthCheckFailed + err.Error()
		klog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, s)
		return err
	}

	if !health.Initialized || health.Sealed {
		klog.V(4).Infof("%s: %s: health: %v", v.issuer.GetObjectMeta().Name, messageVaultStatusVerificationFailed, health)
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageVaultStatusVerificationFailed)
		return fmt.Errorf(messageVaultStatusVerificationFailed)
	}

	klog.Info(messageVaultVerified)
	apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successVaultVerified, messageVaultVerified)
	return nil
}
