/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/issuers"
)

const (
	IssuerControllerName        = "IssuerSelfSigned"
	ClusterIssuerControllerName = "ClusterIssuerSelfSigned"

	messageIsReady = "IsReady"
)

var _ issuers.IssuerBackend = &SelfSigned{}

// SelfSigned is an Issuer implementation the simply self-signs Certificates.
type SelfSigned struct{}

func New(*controllerpkg.Context) issuers.IssuerBackend {
	return new(SelfSigned)
}

func init() {
	issuers.RegisterIssuerBackend(IssuerControllerName, ClusterIssuerControllerName, New)
}

func (s *SelfSigned) Setup(ctx context.Context, issuer cmapi.GenericIssuer) error {
	apiutil.SetIssuerCondition(issuer, cmapi.IssuerConditionReady, cmmeta.ConditionTrue, messageIsReady, "")
	return nil
}

func (s *SelfSigned) TypeChecker(issuer cmapi.GenericIssuer) bool {
	return issuer.GetSpec().SelfSigned != nil
}

func (s *SelfSigned) SecretChecker(cmapi.GenericIssuer, *corev1.Secret) bool {
	return false
}
