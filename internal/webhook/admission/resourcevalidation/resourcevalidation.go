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

package resourcevalidation

import (
	"context"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	acmevalidation "github.com/cert-manager/cert-manager/internal/apis/acme/validation"
	cmvalidation "github.com/cert-manager/cert-manager/internal/apis/certmanager/validation"
	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	admission "github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

type resourceValidation struct {
	*admission.Handler

	validationMappings map[schema.GroupVersionResource]validationPair
}

var _ admission.ValidationInterface = &resourceValidation{}

var certificateGVR = certmanagerv1.SchemeGroupVersion.WithResource("certificates")
var certificateRequestGVR = certmanagerv1.SchemeGroupVersion.WithResource("certificaterequests")
var issuerGVR = certmanagerv1.SchemeGroupVersion.WithResource("issuers")
var clusterIssuerGVR = certmanagerv1.SchemeGroupVersion.WithResource("clusterissuers")
var orderGVR = acmev1.SchemeGroupVersion.WithResource("orders")
var challengeGVR = acmev1.SchemeGroupVersion.WithResource("challenges")

type validateCreateFunc func(a *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, []string)
type validateUpdateFunc func(a *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, []string)

type validationPair struct {
	create validateCreateFunc
	update validateUpdateFunc
}

func newValidationPair(create validateCreateFunc, update validateUpdateFunc) validationPair {
	return validationPair{create: create, update: update}
}

var validationMapping = map[schema.GroupVersionResource]validationPair{
	certificateGVR:        newValidationPair(cmvalidation.ValidateCertificate, cmvalidation.ValidateUpdateCertificate),
	certificateRequestGVR: newValidationPair(cmvalidation.ValidateCertificateRequest, cmvalidation.ValidateUpdateCertificateRequest),
	issuerGVR:             newValidationPair(cmvalidation.ValidateIssuer, cmvalidation.ValidateUpdateIssuer),
	clusterIssuerGVR:      newValidationPair(cmvalidation.ValidateClusterIssuer, cmvalidation.ValidateUpdateClusterIssuer),
	orderGVR:              newValidationPair(acmevalidation.ValidateOrder, acmevalidation.ValidateOrderUpdate),
	challengeGVR:          newValidationPair(acmevalidation.ValidateChallenge, acmevalidation.ValidateChallengeUpdate),
}

func NewPlugin() admission.Interface {
	return &resourceValidation{
		Handler: admission.NewHandler(admissionv1.Create, admissionv1.Update),
	}
}

func (p resourceValidation) Validate(_ context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
	requestResource := schema.GroupVersionResource{
		Group:    request.RequestResource.Group,
		Version:  request.RequestResource.Version,
		Resource: request.RequestResource.Resource,
	}

	pair, ok := validationMapping[requestResource]
	if !ok {
		return nil, nil
	}

	switch request.Operation {
	case admissionv1.Create:
		if pair.create == nil {
			return nil, nil
		}
		errs, warnings := pair.create(&request, obj)
		return warnings, errs.ToAggregate()
	case admissionv1.Update:
		if pair.update == nil {
			return nil, nil
		}
		errs, warnings := pair.update(&request, oldObj, obj)
		return warnings, errs.ToAggregate()
	}

	return nil, nil
}
