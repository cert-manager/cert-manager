/*
Copyright 2018 The Jetstack cert-manager contributors.

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

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
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

func (v *Vault) Setup(ctx context.Context) (issuer.SetupResponse, error) {
	if v.issuer.GetSpec().Vault == nil {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageVaultConfigRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageVaultConfigRequired)
		return issuer.SetupResponse{}, nil
	}

	// check if Vault server info is specified.
	if v.issuer.GetSpec().Vault.Server == "" ||
		v.issuer.GetSpec().Vault.Path == "" {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageServerAndPathRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageServerAndPathRequired)
		return issuer.SetupResponse{}, nil
	}

	// check if at least one auth method is specified.
	if v.issuer.GetSpec().Vault.Auth.TokenSecretRef.Name == "" &&
		v.issuer.GetSpec().Vault.Auth.AppRole.RoleId == "" &&
		v.issuer.GetSpec().Vault.Auth.AppRole.SecretRef.Name == "" {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messsageAuthFieldsRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messsageAuthFieldsRequired)
		return issuer.SetupResponse{}, nil
	}

	// check if only token auth method is set.
	if v.issuer.GetSpec().Vault.Auth.TokenSecretRef.Name != "" &&
		(v.issuer.GetSpec().Vault.Auth.AppRole.RoleId != "" ||
			v.issuer.GetSpec().Vault.Auth.AppRole.SecretRef.Name != "") {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageAuthFieldRequired)
		return issuer.SetupResponse{}, nil
	}

	// check if all mandatory Vault appRole fields are set.
	if v.issuer.GetSpec().Vault.Auth.TokenSecretRef.Name == "" &&
		(v.issuer.GetSpec().Vault.Auth.AppRole.RoleId == "" ||
			v.issuer.GetSpec().Vault.Auth.AppRole.SecretRef.Name == "") {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageAuthFieldRequired)
		return issuer.SetupResponse{}, nil
	}

	client, err := v.initVaultClient()
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		glog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, s)
		return issuer.SetupResponse{}, err
	}

	health, err := client.Sys().Health()
	if err != nil {
		s := messageVaultHealthCheckFailed + err.Error()
		glog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, s)
		return issuer.SetupResponse{}, err
	}

	if !health.Initialized || health.Sealed {
		glog.V(4).Infof("%s: %s: health: %v", v.issuer.GetObjectMeta().Name, messageVaultStatusVerificationFailed, health)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageVaultStatusVerificationFailed)
		return issuer.SetupResponse{}, fmt.Errorf(messageVaultStatusVerificationFailed)
	}

	glog.Info(messageVaultVerified)
	v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successVaultVerified, messageVaultVerified)
	return issuer.SetupResponse{}, nil
}
