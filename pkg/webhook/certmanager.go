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

package webhook

import (
	"k8s.io/apimachinery/pkg/runtime/schema"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	acmeval "github.com/jetstack/cert-manager/pkg/internal/apis/acme/validation"
	"github.com/jetstack/cert-manager/pkg/internal/apis/certmanager/validation"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers"
)

var Validators = map[schema.GroupKind]handlers.Validator{
	gk(cmapi.SchemeGroupVersion, cmapi.CertificateKind):        certificateValidator,
	gk(cmapi.SchemeGroupVersion, cmapi.CertificateRequestKind): certificateRequestValidator,
	gk(cmapi.SchemeGroupVersion, cmapi.IssuerKind):             issuerValidator,
	gk(cmapi.SchemeGroupVersion, cmapi.ClusterIssuerKind):      clusterIssuerValidator,
	gk(cmacme.SchemeGroupVersion, cmacme.OrderKind):            orderValidator,
	gk(cmacme.SchemeGroupVersion, cmacme.ChallengeKind):        challengeValidator,
}

var (
	certificateValidator        = handlers.ValidatorFunc(&cmapi.Certificate{}, validation.ValidateCertificate, nil)
	certificateRequestValidator = handlers.ValidatorFunc(&cmapi.CertificateRequest{}, validation.ValidateCertificateRequest, nil)
	issuerValidator             = handlers.ValidatorFunc(&cmapi.Issuer{}, validation.ValidateIssuer, nil)
	clusterIssuerValidator      = handlers.ValidatorFunc(&cmapi.ClusterIssuer{}, validation.ValidateClusterIssuer, nil)
	orderValidator              = handlers.ValidatorFunc(&cmacme.Order{}, nil, acmeval.ValidateOrderUpdate)
	challengeValidator          = handlers.ValidatorFunc(&cmacme.Challenge{}, nil, acmeval.ValidateChallengeUpdate)
)

func gk(gv schema.GroupVersion, kind string) schema.GroupKind {
	return schema.GroupKind{
		Group: gv.Group,
		Kind:  kind,
	}
}
