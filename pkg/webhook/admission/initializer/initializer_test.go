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

/*
Copyright 2017 The Kubernetes Authors.
Derived from https://github.com/kubernetes/kubernetes/blob/9d0d2e8ece9bdd0cd8c23be2f36eee5473afc648/staging/src/k8s.io/apiserver/pkg/admission/initializer/initializer_test.go
*/

package initializer_test

import (
	"context"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/featuregate"

	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission/initializer"
)

// TestWantsFeature ensures that the feature gates are injected
// when the WantsFeatures interface is implemented by a plugin.
func TestWantsFeatures(t *testing.T) {
	target := initializer.New(nil, nil, nil, featuregate.NewFeatureGate())
	wantFeaturesAdmission := &WantsFeaturesAdmission{}
	target.Initialize(wantFeaturesAdmission)
	if wantFeaturesAdmission.features == nil {
		t.Errorf("expected features to be initialized but found nil")
	}
}

// TestWantsAuthorizer ensures that the authorizer is injected
// when the WantsAuthorizer interface is implemented by a plugin.
func TestWantsAuthorizer(t *testing.T) {
	target := initializer.New(nil, nil, &TestAuthorizer{}, nil)
	wantAuthorizerAdmission := &WantAuthorizerAdmission{}
	target.Initialize(wantAuthorizerAdmission)
	if wantAuthorizerAdmission.auth == nil {
		t.Errorf("expected authorizer to be initialized but found nil")
	}
}

// TestWantsExternalKubeClientSet ensures that the clientset is injected
// when the WantsExternalKubeClientSet interface is implemented by a plugin.
func TestWantsExternalKubeClientSet(t *testing.T) {
	cs := &fake.Clientset{}
	target := initializer.New(cs, nil, &TestAuthorizer{}, nil)
	wantExternalKubeClientSet := &WantExternalKubeClientSet{}
	target.Initialize(wantExternalKubeClientSet)
	if wantExternalKubeClientSet.cs != cs {
		t.Errorf("expected clientset to be initialized")
	}
}

// TestWantsExternalKubeInformerFactory ensures that the informer factory is injected
// when the WantsExternalKubeInformerFactory interface is implemented by a plugin.
func TestWantsExternalKubeInformerFactory(t *testing.T) {
	cs := &fake.Clientset{}
	sf := informers.NewSharedInformerFactory(cs, time.Duration(1)*time.Second)
	target := initializer.New(cs, sf, &TestAuthorizer{}, nil)
	wantExternalKubeInformerFactory := &WantExternalKubeInformerFactory{}
	target.Initialize(wantExternalKubeInformerFactory)
	if wantExternalKubeInformerFactory.sf != sf {
		t.Errorf("expected informer factory to be initialized")
	}
}

// WantExternalKubeInformerFactory is a test stub that fulfills the WantsExternalKubeInformerFactory interface
type WantExternalKubeInformerFactory struct {
	sf informers.SharedInformerFactory
}

func (self *WantExternalKubeInformerFactory) SetExternalKubeInformerFactory(sf informers.SharedInformerFactory) {
	self.sf = sf
}
func (self *WantExternalKubeInformerFactory) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error) {
	return nil, nil
}
func (self *WantExternalKubeInformerFactory) Handles(o admissionv1.Operation) bool { return false }
func (self *WantExternalKubeInformerFactory) ValidateInitialization() error        { return nil }

var _ admission.Interface = &WantExternalKubeInformerFactory{}
var _ initializer.WantsExternalKubeInformerFactory = &WantExternalKubeInformerFactory{}

// WantExternalKubeClientSet is a test stub that fulfills the WantsExternalKubeClientSet interface
type WantExternalKubeClientSet struct {
	cs kubernetes.Interface
}

func (self *WantExternalKubeClientSet) SetExternalKubeClientSet(cs kubernetes.Interface) {
	self.cs = cs
}
func (self *WantExternalKubeClientSet) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error) {
	return nil, nil
}
func (self *WantExternalKubeClientSet) Handles(o admissionv1.Operation) bool { return false }
func (self *WantExternalKubeClientSet) ValidateInitialization() error        { return nil }

var _ admission.Interface = &WantExternalKubeClientSet{}
var _ initializer.WantsExternalKubeClientSet = &WantExternalKubeClientSet{}

// WantAuthorizerAdmission is a test stub that fulfills the WantsAuthorizer interface.
type WantAuthorizerAdmission struct {
	auth authorizer.Authorizer
}

func (self *WantAuthorizerAdmission) SetAuthorizer(a authorizer.Authorizer) { self.auth = a }
func (self *WantAuthorizerAdmission) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error) {
	return nil, nil
}
func (self *WantAuthorizerAdmission) Handles(o admissionv1.Operation) bool { return false }
func (self *WantAuthorizerAdmission) ValidateInitialization() error        { return nil }

var _ admission.Interface = &WantAuthorizerAdmission{}
var _ initializer.WantsAuthorizer = &WantAuthorizerAdmission{}

// TestAuthorizer is a test stub that fulfills the WantsAuthorizer interface.
type TestAuthorizer struct{}

func (t *TestAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	return authorizer.DecisionNoOpinion, "", nil
}

// WantsFeaturesAdmission is a test stub that fulfills the WantsFeatures interface.
type WantsFeaturesAdmission struct {
	features featuregate.FeatureGate
}

func (self *WantsFeaturesAdmission) InspectFeatureGates(gate featuregate.FeatureGate) {
	self.features = gate
}
func (self *WantsFeaturesAdmission) Validate(ctx context.Context, request admissionv1.AdmissionRequest, oldObj, obj runtime.Object) (warnings []string, err error) {
	return nil, nil
}
func (self *WantsFeaturesAdmission) Handles(o admissionv1.Operation) bool { return false }
func (self *WantsFeaturesAdmission) ValidateInitialization() error        { return nil }

var _ admission.Interface = &WantsFeaturesAdmission{}
var _ initializer.WantsFeatures = &WantsFeaturesAdmission{}
