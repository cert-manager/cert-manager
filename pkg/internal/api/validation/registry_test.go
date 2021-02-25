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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/internal/api/validation"
	cmapiinternal "github.com/cert-manager/cert-manager/pkg/internal/apis/certmanager"
	"github.com/cert-manager/cert-manager/pkg/webhook"
)

var (
	// use the webhook's Scheme during test fixtures as it has all internal and
	// external cert-manager kinds registered
	scheme = webhook.Scheme
)

func TestValidateType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called := false
	utilruntime.Must(reg.AddValidateFunc(&cmapi.Certificate{}, func(obj runtime.Object) field.ErrorList {
		called = true
		return nil
	}))
	errs := reg.Validate(&cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
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
	utilruntime.Must(reg.AddValidateFunc(&cmapi.Certificate{}, func(obj runtime.Object) field.ErrorList {
		called1 = true
		return nil
	}))
	utilruntime.Must(reg.AddValidateFunc(&cmapi.Certificate{}, func(obj runtime.Object) field.ErrorList {
		called2 = true
		return nil
	}))
	utilruntime.Must(reg.AddValidateFunc(&cmapiinternal.Certificate{}, func(obj runtime.Object) field.ErrorList {
		calledInternal = true
		return nil
	}))
	errs := reg.Validate(&cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
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
	utilruntime.Must(reg.AddValidateUpdateFunc(&cmapi.Certificate{}, func(_, _ runtime.Object) field.ErrorList {
		called1 = true
		return nil
	}))
	utilruntime.Must(reg.AddValidateUpdateFunc(&cmapi.Certificate{}, func(_, _ runtime.Object) field.ErrorList {
		called2 = true
		return nil
	}))
	utilruntime.Must(reg.AddValidateUpdateFunc(&cmapiinternal.Certificate{}, func(_, _ runtime.Object) field.ErrorList {
		calledInternal = true
		return nil
	}))
	errs := reg.ValidateUpdate(&cmapi.Certificate{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
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
	utilruntime.Must(reg.AddValidateUpdateFunc(&cmapi.Certificate{}, func(oldObj, obj runtime.Object) field.ErrorList {
		called = true
		return nil
	}))
	errs := reg.ValidateUpdate(&cmapi.Certificate{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if !called {
		t.Errorf("expected registered validation function to run but it did not")
	}
}

func TestValidateTypeReturnsErrors(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called := false
	expectedErr := field.InternalError(nil, fmt.Errorf("failed"))
	utilruntime.Must(reg.AddValidateFunc(&cmapi.Certificate{}, func(obj runtime.Object) field.ErrorList {
		called = true
		return field.ErrorList{expectedErr}
	}))
	errs := reg.Validate(&cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) != 1 {
		t.Error("expected to get an error but got none")
	} else if err := errs[0]; err.Error() != expectedErr.Error() {
		t.Errorf("expected error to be %q but got %q", expectedErr.Error(), err.Error())
	}
	if !called {
		t.Errorf("expected registered validation function to run but it did not")
	}
}

func TestValidateInternalType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	called := false
	utilruntime.Must(reg.AddValidateFunc(&cmapiinternal.Certificate{}, func(obj runtime.Object) field.ErrorList {
		called = true
		return nil
	}))
	errs := reg.Validate(&cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
	if !called {
		t.Errorf("expected registered internal validation function to run for external type but it did not")
	}
}

func TestValidateNoErrorNoneRegistered(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	errs := reg.Validate(&cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
}

func TestValidateUpdateNoErrorNoneRegistered(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	errs := reg.ValidateUpdate(&cmapi.Certificate{}, &cmapi.Certificate{}, cmapi.SchemeGroupVersion.WithKind("Certificate"))
	if len(errs) > 0 {
		t.Errorf("expected to not get an error but got: %v", errs.ToAggregate())
	}
}

func TestValidateUnrecognisedType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	err := reg.AddValidateFunc(&corev1.Pod{}, func(obj runtime.Object) field.ErrorList {
		return nil
	})
	if err == nil {
		t.Errorf("expected to get an error but did not")
	}
}

func TestValidateUpdateUnrecognisedType(t *testing.T) {
	reg := validation.NewRegistry(scheme)
	err := reg.AddValidateUpdateFunc(&corev1.Pod{}, func(oldObj, obj runtime.Object) field.ErrorList {
		return nil
	})
	if err == nil {
		t.Errorf("expected to get an error but did not")
	}
}
