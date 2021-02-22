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

package vault

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/issuers"
	vaultinternal "github.com/jetstack/cert-manager/pkg/internal/vault"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	IssuerControllerName        = "IssuerVault"
	ClusterIssuerControllerName = "ClusterIssuerVault"

	successVaultVerified = "VaultVerified"
	messageVaultVerified = "Vault verified"

	messageVaultClientInitFailed         = "Failed to initialize Vault client: "
	messageVaultHealthCheckFailed        = "Failed to call Vault health check: "
	messageVaultStatusVerificationFailed = "Vault is not initialized or is sealed"
	messageServerAndPathRequired         = "Vault server and path are required fields"
	messageAuthFieldRequired             = "Vault tokenSecretRef, appRole, or kubernetes is required"
	messageAuthOneFieldRequired          = "Multiple auth methods cannot be set on the same Vault issuer"

	errorVault = "VaultError"
)

var _ issuers.Issuer = &Vault{}

type Vault struct {
	// Defines the issuer specific options set on the controller
	issuerOptions controllerpkg.IssuerOptions

	secretsLister corelisters.SecretLister
	recorder      record.EventRecorder
}

func New(ctx *controllerpkg.Context) issuers.Issuer {
	return &Vault{
		issuerOptions: ctx.IssuerOptions,
		secretsLister: ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
		recorder:      ctx.Recorder,
	}
}

// Register this Issuer with the issuer factory
func init() {
	// create issuer controller for ca
	controllerpkg.Register(IssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, IssuerControllerName).
			For(issuers.New(IssuerControllerName, cmapi.IssuerKind, New(ctx))).
			Complete()
	})

	// create cluster issuer controller for ca
	controllerpkg.Register(ClusterIssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ClusterIssuerControllerName).
			For(issuers.New(ClusterIssuerControllerName, cmapi.ClusterIssuerKind, New(ctx))).
			Complete()
	})
}

func (v *Vault) Setup(ctx context.Context, issuer cmapi.GenericIssuer) error {
	log := logf.FromContext(ctx, "setup").WithName(issuer.GetName())

	// check if Vault server info is specified.
	if issuer.GetSpec().Vault.Server == "" ||
		issuer.GetSpec().Vault.Path == "" {
		log.V(logf.WarnLevel).Info(messageServerAndPathRequired)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageServerAndPathRequired)
		return nil
	}

	tokenAuth := issuer.GetSpec().Vault.Auth.TokenSecretRef
	appRoleAuth := issuer.GetSpec().Vault.Auth.AppRole
	kubeAuth := issuer.GetSpec().Vault.Auth.Kubernetes

	// check if at least one auth method is specified.
	if tokenAuth == nil && appRoleAuth == nil && kubeAuth == nil {
		log.V(logf.WarnLevel).Info(messageAuthFieldRequired)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	// check only one auth method set
	if (tokenAuth != nil && appRoleAuth != nil) ||
		(tokenAuth != nil && kubeAuth != nil) ||
		(appRoleAuth != nil && kubeAuth != nil) {
		log.V(logf.WarnLevel).Info(messageAuthFieldRequired)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	// check if all mandatory Vault Token fields are set.
	if tokenAuth != nil && len(tokenAuth.Name) == 0 {
		log.V(logf.WarnLevel).Info(messageAuthFieldRequired)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	// check if all mandatory Vault appRole fields are set.
	if appRoleAuth != nil && (len(appRoleAuth.RoleId) == 0 || len(appRoleAuth.SecretRef.Name) == 0) {
		log.V(logf.WarnLevel).Info(messageAuthFieldRequired)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	// check if all mandatory Vault Kubernetes fields are set.
	if kubeAuth != nil && (len(kubeAuth.SecretRef.Name) == 0 || len(kubeAuth.Role) == 0) {
		log.V(logf.WarnLevel).Info(messageAuthFieldRequired)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageAuthFieldRequired)
		return nil
	}

	resourceNamespace := v.issuerOptions.ResourceNamespace(issuer)
	client, err := vaultinternal.New(resourceNamespace, v.secretsLister, issuer)
	if err != nil {
		s := messageVaultClientInitFailed + err.Error()
		log.V(logf.WarnLevel).Info(s)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, s)
		return err
	}

	health, err := client.Sys().Health()
	if err != nil {
		s := messageVaultHealthCheckFailed + err.Error()
		log.V(logf.WarnLevel).Info(s)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, s)
		return err
	}

	if !health.Initialized || health.Sealed {
		log.V(logf.WarnLevel).Info(messageVaultStatusVerificationFailed, "health", health)
		apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionFalse, errorVault, messageVaultStatusVerificationFailed)
		return fmt.Errorf(messageVaultStatusVerificationFailed)
	}

	log.V(logf.DebugLevel).Info(messageVaultVerified)
	apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, successVaultVerified, messageVaultVerified)
	return nil
}

func (v *Vault) Implements(issuer cmapi.GenericIssuer) bool {
	return issuer.GetSpec().Vault != nil
}

func (v *Vault) ReferencesSecret(issuer cmapi.GenericIssuer, secret *corev1.Secret) bool {
	vaultSpec := issuer.GetSpec().Vault
	if vaultSpec == nil {
		return false
	}

	if v.issuerOptions.ResourceNamespace(issuer) != secret.Namespace {
		return false
	}

	if tokenRef := vaultSpec.Auth.TokenSecretRef; tokenRef != nil &&
		tokenRef.Name == secret.Name {
		return true
	}

	if appRole := vaultSpec.Auth.AppRole; appRole != nil &&
		appRole.SecretRef.Name == secret.Name {
		return true
	}

	if kubernetes := vaultSpec.Auth.Kubernetes; kubernetes != nil &&
		kubernetes.SecretRef.Name == secret.Name {
		return true
	}

	return false
}
