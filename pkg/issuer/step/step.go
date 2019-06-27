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

package step

import (
	"bytes"
	"fmt"

	"github.com/jetstack/cert-manager/pkg/api/util"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/smallstep/certificates/ca"
	corelisters "k8s.io/client-go/listers/core/v1"
)

func init() {
	issuer.RegisterIssuer(util.IssuerStep, NewStep)
}

// Step is the issuer used with step certificates
// (https://github.com/smallstep/certificates). It contains a JWK provisioner
// that will generate JWT tokens that will be interchanged for TLS certificates.
type Step struct {
	*controller.Context
	issuer            certmanager.GenericIssuer
	secretsLister     corelisters.SecretLister
	resourceNamespace string
	provisioner       *ca.Provisioner
}

// NewStep initializes the step certificates issuer.
func NewStep(ctx *controller.Context, issuer certmanager.GenericIssuer) (issuer.Interface, error) {
	spec := issuer.GetSpec().Step
	switch {
	case spec == nil:
		return nil, fmt.Errorf("step configuration not found")
	case spec.URL == "":
		return nil, fmt.Errorf("step.url cannot be empty")
	case spec.Provisioner.Name == "":
		return nil, fmt.Errorf("step.provisioner.name cannot be empty")
	case spec.Provisioner.KeyID == "":
		return nil, fmt.Errorf("step.provisioner.kid cannot be empty")
	case spec.Provisioner.PasswordRef.Name == "":
		return nil, fmt.Errorf("step.provisioner.passwordRef.name cannot be empty")
	case spec.Provisioner.PasswordRef.Key == "":
		return nil, fmt.Errorf("step.provisioner.passwordRef.key cannot be empty")
	}

	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()
	resourceNamespace := ctx.IssuerOptions.ResourceNamespace(issuer)

	secrets, err := secretsLister.Secrets(resourceNamespace).Get(spec.Provisioner.PasswordRef.Name)
	if err != nil {
		return nil, fmt.Errorf("error loading secret %s: %v", spec.Provisioner.PasswordRef.Name, err)
	}

	password, ok := secrets.Data[spec.Provisioner.PasswordRef.Key]
	if !ok {
		return nil, fmt.Errorf("error loading secret %s: no data found", spec.Provisioner.PasswordRef.Name)
	}
	password = bytes.TrimSpace(password)

	var options []ca.ClientOption
	if len(spec.CABundle) > 0 {
		options = append(options, ca.WithCABundle(spec.CABundle))
	}

	provisioner, err := ca.NewProvisioner(spec.Provisioner.Name, spec.Provisioner.KeyID, spec.URL, password, options...)
	if err != nil {
		util.SetIssuerCondition(issuer, certmanager.IssuerConditionReady, certmanager.ConditionFalse, "ErrorProvisioner", fmt.Sprintf("Provisioner configuration error: %v", err))
		return nil, err
	}

	return &Step{
		Context:           ctx,
		issuer:            issuer,
		secretsLister:     secretsLister,
		resourceNamespace: resourceNamespace,
		provisioner:       provisioner,
	}, nil
}
