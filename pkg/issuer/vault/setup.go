package vault

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

const (
	successVaultVerified = "VaultVerified"
	messageVaultVerified = "Vault verified"

	errorVault = "VaultError"

	messageVaultClientInitFailed         = "Failed to initialize Vault client: "
	messageVaultHealthCheckFailed        = "Failed to call Vault health check: "
	messageVaultStatusVerificationFailed = "Vault is not initialized or is sealed: "
	messageVaultConfigRequired           = "Vault config cannot be empty"
	messageServerAndPathRequired         = "Vault server and path are required fields"
	messsageAuthFieldsRequired           = "Vault tokenSecretRef or appRole is required"
	messageAuthFieldRequired             = "Vault tokenSecretRef and appRole cannot be set on the same issuer"
)

func (v *Vault) Setup(ctx context.Context) error {
	if v.issuer.GetSpec().Vault == nil {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageVaultConfigRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageVaultConfigRequired)
		return fmt.Errorf(messageVaultConfigRequired)
	}

	if v.issuer.GetSpec().Vault.Server == "" ||
		v.issuer.GetSpec().Vault.Path == "" {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageServerAndPathRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageServerAndPathRequired)
		return fmt.Errorf(messageVaultConfigRequired)
	}

	if v.issuer.GetSpec().Vault.Auth.TokenSecretRef.Name == "" &&
		v.issuer.GetSpec().Vault.Auth.AppRole.RoleId == "" &&
		v.issuer.GetSpec().Vault.Auth.AppRole.SecretRef.Name == "" {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messsageAuthFieldsRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messsageAuthFieldsRequired)
		return fmt.Errorf(messsageAuthFieldsRequired)
	}

	if v.issuer.GetSpec().Vault.Auth.TokenSecretRef.Name != "" &&
		(v.issuer.GetSpec().Vault.Auth.AppRole.RoleId != "" ||
			v.issuer.GetSpec().Vault.Auth.AppRole.SecretRef.Name != "") {
		glog.Infof("%s: %s", v.issuer.GetObjectMeta().Name, messageAuthFieldRequired)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, messageAuthFieldRequired)
		return fmt.Errorf(messageAuthFieldRequired)
	}

	client, err := v.initVaultClient()
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		glog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, s)
		return err
	}

	health, err := client.Sys().Health()
	if err != nil {
		s := messageVaultHealthCheckFailed + err.Error()
		glog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, s)
		return err
	}

	if !health.Initialized || health.Sealed {
		s := messageVaultStatusVerificationFailed + err.Error()
		glog.V(4).Infof("%s: %s", v.issuer.GetObjectMeta().Name, s)
		v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorVault, s)
		return err
	}

	glog.Info(messageVaultVerified)
	v.issuer.UpdateStatusCondition(v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successVaultVerified, messageVaultVerified)
	return nil
}
