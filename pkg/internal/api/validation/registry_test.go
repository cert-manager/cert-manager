/*
Copyright 2020 The cert-manager Authors.

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

package validation_test

import (
	"fmt"
	"reflect"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
	cmapiinternal "github.com/jetstack/cert-manager/pkg/internal/apis/certmanager"
	"github.com/jetstack/cert-manager/pkg/webhook"
)

var (
	// use the webhook's Scheme during test fixtures as it has all internal and
	// external cert-manager kinds registered
	scheme = webhook.Scheme
)

func TestValidateType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called := false
	utilruntime.Must(reg.AddValidateFunc(&cmapi.Certificate{}, func(req *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		called = true
		return nil, nil
	}))
	errs, warnings := reg.Validate(&admissionv1.AdmissionRequest{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if len(warnings) > 0 {
		t.Errorf("expected no warnings but got: %+v", warnings)
	}
	if !called {
		t.Errorf("expected registered validation function to run but it did not")
	}
}

func TestValidateTypeMultiple(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called1 := false
	called2 := false
	calledInternal := false
	utilruntime.Must(reg.AddValidateFunc(&cmapi.Certificate{}, func(req *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		called1 = true
		return nil, nil
	}))
	utilruntime.Must(reg.AddValidateFunc(&cmapi.Certificate{}, func(req *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		called2 = true
		return nil, nil
	}))
	utilruntime.Must(reg.AddValidateFunc(&cmapiinternal.Certificate{}, func(req *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		calledInternal = true
		return nil, nil
	}))
	errs, warnings := reg.Validate(&admissionv1.AdmissionRequest{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if len(warnings) > 0 {
		t.Errorf("expected to not get any warnings but got %+v", warnings)
	}
	if !called1 || !called2 {
		t.Errorf("expected registered validation function to run but it did not")
	}
	if !calledInternal {
		t.Errorf("expected registered internal validation function to run against external type but it did not")
	}
}

func TestValidateUpdateTypeMultiple(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called1 := false
	called2 := false
	calledInternal := false
	utilruntime.Must(reg.AddValidateUpdateFunc(&cmapi.Certificate{}, func(_ *admissionv1.AdmissionRequest, _, _ runtime.Object) (field.ErrorList, validation.WarningList) {
		called1 = true
		return nil, nil
	}))
	utilruntime.Must(reg.AddValidateUpdateFunc(&cmapi.Certificate{}, func(_ *admissionv1.AdmissionRequest, _, _ runtime.Object) (field.ErrorList, validation.WarningList) {
		called2 = true
		return nil, nil
	}))
	utilruntime.Must(reg.AddValidateUpdateFunc(&cmapiinternal.Certificate{}, func(_ *admissionv1.AdmissionRequest, _, _ runtime.Object) (field.ErrorList, validation.WarningList) {
		calledInternal = true
		return nil, nil
	}))
	errs, warnings := reg.ValidateUpdate(&admissionv1.AdmissionRequest{}, &cmapi.Certificate{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if len(warnings) > 0 {
		t.Errorf("expected to not get any warnings but got: %v", warnings)
	}
	if !called1 || !called2 {
		t.Errorf("expected registered validation function to run but it did not")
	}
	if !calledInternal {
		t.Errorf("expected registered internal validation function to run against external type but it did not")
	}
}

func TestValidateUpdateType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called := false
	utilruntime.Must(reg.AddValidateUpdateFunc(&cmapi.Certificate{}, func(_ *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		called = true
		return nil, nil
	}))
	errs, warnings := reg.ValidateUpdate(&admissionv1.AdmissionRequest{}, &cmapi.Certificate{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if len(warnings) > 0 {
		t.Errorf("expected to not get any warnings but got %+v", warnings)
	}
	if !called {
		t.Errorf("expected registered validation function to run but it did not")
	}
}

func TestValidateTypeReturnsErrorsAndWarnings(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called := false
	expectedErr := field.InternalError(nil, fmt.Errorf("failed"))
	expectedWarnings := validation.WarningList{"test warning"}
	utilruntime.Must(reg.AddValidateFunc(&cmapi.Certificate{}, func(_ *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		called = true
		return field.ErrorList{expectedErr}, expectedWarnings
	}))
	errs, warnings := reg.Validate(&admissionv1.AdmissionRequest{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) != 1 {
		t.Error("expected to get an error but got none")
	} else if err := errs[0]; err.Error() != expectedErr.Error() {
		t.Errorf("expected error to be %q but got %q", expectedErr.Error(), err.Error())
	}
	if !reflect.DeepEqual(warnings, expectedWarnings) {
		t.Errorf("expected warnings %+#v got %+#v", expectedWarnings, warnings)
	}
	if !called {
		t.Errorf("expected registered validation function to run but it did not")
	}
}

func TestValidateInternalType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called := false
	utilruntime.Must(reg.AddValidateFunc(&cmapiinternal.Certificate{}, func(_ *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		called = true
		return nil, nil
	}))
	errs, warnings := reg.Validate(&admissionv1.AdmissionRequest{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if len(warnings) > 0 {
		t.Errorf("expected to not get any warnings but got %+v", warnings)
	}
	if !called {
		t.Errorf("expected registered internal validation function to run for external type but it did not")
	}
}

func TestValidateNoErrorNoneRegistered(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	errs, warnings := reg.Validate(&admissionv1.AdmissionRequest{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if len(warnings) > 0 {
		t.Errorf("expected to not get any warnings but got: %+v", warnings)
	}
}

func TestValidateUpdateNoErrorNoneRegistered(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	errs, warnings := reg.ValidateUpdate(&admissionv1.AdmissionRequest{}, &cmapi.Certificate{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if len(warnings) > 0 {
		t.Errorf("exptected to not get any warnings but got: %+v", warnings)
	}
}

func TestValidateUnrecognisedType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	err := reg.AddValidateFunc(&corev1.Pod{}, func(_ *admissionv1.AdmissionRequest, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		return nil, nil
	})
	if err == nil {
		t.Errorf("expected to get an error but did not")
	}
}

func TestValidateUpdateUnrecognisedType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	err := reg.AddValidateUpdateFunc(&corev1.Pod{}, func(_ *admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (field.ErrorList, validation.WarningList) {
		return nil, nil
	})
	if err == nil {
		t.Errorf("expected to get an error but did not")
	}
}
