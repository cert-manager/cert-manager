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
	"fmt"
	"reflect"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/cert-manager/cert-manager/internal/apis/acme"
	acmevalidation "github.com/cert-manager/cert-manager/internal/apis/acme/validation"
	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	cmvalidation "github.com/cert-manager/cert-manager/internal/apis/certmanager/validation"
	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	admission "github.com/cert-manager/cert-manager/pkg/webhook/admission"
)

type resourceValidation struct {
	*admission.Handler
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

	// objType is the concrete type create/update expect obj (and, for
	// update, oldObj) to be. The webhook decoder decodes strictly by the
	// request's payload Kind, not by Resource (see custom_decoder.go), so a
	// crafted request whose resource and object kind disagree (e.g.
	// resource: certificates with an object of kind CertificateRequest)
	// reaches here with an obj of the wrong type. Validate checks obj/oldObj
	// against objType before dispatching, turning that mismatch into a clean
	// error instead of a panic from the bare type assertions inside the
	// create/update funcs below.
	objType reflect.Type
}

func newValidationPair(objType runtime.Object, create validateCreateFunc, update validateUpdateFunc) validationPair {
	return validationPair{objType: reflect.TypeOf(objType), create: create, update: update}
}

// checkType returns an error if obj is not of type want. label identifies
// which of Validate's parameters (obj/oldObj) was checked, for the error
// message.
func checkType(obj runtime.Object, want reflect.Type, label string) error {
	if reflect.TypeOf(obj) != want {
		return fmt.Errorf("internal error: %s in admission request is not of type %s", label, want)
	}
	return nil
}

var validationMapping = map[schema.GroupVersionResource]validationPair{
	certificateGVR:        newValidationPair(&certmanager.Certificate{}, cmvalidation.ValidateCertificate, cmvalidation.ValidateUpdateCertificate),
	certificateRequestGVR: newValidationPair(&certmanager.CertificateRequest{}, cmvalidation.ValidateCertificateRequest, cmvalidation.ValidateUpdateCertificateRequest),
	issuerGVR:             newValidationPair(&certmanager.Issuer{}, cmvalidation.ValidateIssuer, cmvalidation.ValidateUpdateIssuer),
	clusterIssuerGVR:      newValidationPair(&certmanager.ClusterIssuer{}, cmvalidation.ValidateClusterIssuer, cmvalidation.ValidateUpdateClusterIssuer),
	orderGVR:              newValidationPair(&acme.Order{}, acmevalidation.ValidateOrder, acmevalidation.ValidateOrderUpdate),
	challengeGVR:          newValidationPair(&acme.Challenge{}, acmevalidation.ValidateChallenge, acmevalidation.ValidateChallengeUpdate),
}

func NewPlugin() admission.Interface {
	return &resourceValidation{
		Handler: admission.NewHandler(admissionv1.Create, admissionv1.Update),
	}
}

func (p resourceValidation) Validate(_ context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) ([]string, error) {
	if admission.IsResourceUnset(request.Resource) {
		return nil, admission.ErrResourceUnset
	}

	gvr := schema.GroupVersionResource(request.Resource)

	pair, ok := validationMapping[gvr]
	if !ok {
		return nil, nil
	}

	switch request.Operation {
	case admissionv1.Create:
		if pair.create == nil {
			return nil, nil
		}
		if err := checkType(obj, pair.objType, "object"); err != nil {
			return nil, err
		}
		errs, warnings := pair.create(&request, obj)
		return warnings, errs.ToAggregate()
	case admissionv1.Update:
		if pair.update == nil {
			return nil, nil
		}
		if err := checkType(obj, pair.objType, "object"); err != nil {
			return nil, err
		}
		if err := checkType(oldObj, pair.objType, "oldObject"); err != nil {
			return nil, err
		}
		errs, warnings := pair.update(&request, oldObj, obj)
		return warnings, errs.ToAggregate()
	default:
		return nil, nil
	}
}
