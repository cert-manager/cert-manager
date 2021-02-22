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

package selfsigned

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/issuers"
)

const (
	IssuerControllerName        = "IssuerSelfSigned"
	ClusterIssuerControllerName = "ClusterIssuerSelfSigned"

	messageIsReady = "IsReady"
)

var _ issuers.Issuer = &SelfSigned{}

// SelfSigned is an Issuer implementation the simply self-signs Certificates.
type SelfSigned struct{}

func New(*controllerpkg.Context) issuers.Issuer {
	return new(SelfSigned)
}

func init() {
	// create issuer controller for selfsigned
	controllerpkg.Register(IssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, IssuerControllerName).
			For(issuers.New(IssuerControllerName, cmapi.IssuerKind, New(ctx))).
			Complete()
	})

	// create cluster issuer controller for selfsigned
	controllerpkg.Register(ClusterIssuerControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ClusterIssuerControllerName).
			For(issuers.New(ClusterIssuerControllerName, cmapi.ClusterIssuerKind, New(ctx))).
			Complete()
	})
}

func (s *SelfSigned) Setup(ctx context.Context, issuer cmapi.GenericIssuer) error {
	apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, messageIsReady, "")
	return nil
}

func (s *SelfSigned) Implements(issuer cmapi.GenericIssuer) bool {
	return issuer.GetSpec().SelfSigned != nil
}

func (s *SelfSigned) ReferencesSecret(cmapi.GenericIssuer, *corev1.Secret) bool {
	return false
}
