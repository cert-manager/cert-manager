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

package admission_test

import (
	"fmt"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cert-manager/cert-manager/pkg/webhook/admission"
	"github.com/cert-manager/cert-manager/pkg/webhook/admission/initializer"
)

func TestPlugins_InitializesNamedOnly(t *testing.T) {
	scheme := runtime.NewScheme()
	p := admission.NewPlugins(scheme)

	testPlugin1 := &testPlugin{}
	p.Register("TestPlugin1", func() (admission.Interface, error) {
		return testPlugin1, nil
	})

	testPlugin2 := &testPlugin{
		initErr: fmt.Errorf("failed init"),
	}
	p.Register("TestPlugin2", func() (admission.Interface, error) {
		return testPlugin2, nil
	})

	// only initialize TestPlugin1
	_, err := p.NewFromPlugins([]string{"TestPlugin1"}, initializer.New(fake.NewSimpleClientset(), nil, nil, nil))
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}
	if testPlugin1.kc == nil {
		t.Errorf("expected TestPlugin1 to be initialized")
	}
	if testPlugin2.kc != nil {
		t.Errorf("expected TestPlugin2 to not be initialized")
	}
}

func TestPlugins_FailsIfAnyPluginFails(t *testing.T) {
	scheme := runtime.NewScheme()
	p := admission.NewPlugins(scheme)

	testPlugin1 := &testPlugin{}
	p.Register("TestPlugin1", func() (admission.Interface, error) {
		return testPlugin1, nil
	})

	testPlugin2 := &testPlugin{
		initErr: fmt.Errorf("failed init"),
	}
	p.Register("TestPlugin2", func() (admission.Interface, error) {
		return testPlugin2, nil
	})

	// only initialize TestPlugin1
	_, err := p.NewFromPlugins([]string{"TestPlugin1", "TestPlugin2"}, initializer.New(fake.NewSimpleClientset(), nil, nil, nil))
	if err == nil {
		t.Errorf("expected an error but got none")
	}
	if testPlugin1.kc == nil {
		t.Errorf("expected TestPlugin1 to be initialized")
	}
	if testPlugin2.kc == nil {
		t.Errorf("expected TestPlugin2 to be initialized")
	}
}

func TestPlugins_FailsNonExistingPlugin(t *testing.T) {
	scheme := runtime.NewScheme()
	p := admission.NewPlugins(scheme)

	testPlugin1 := &testPlugin{}
	p.Register("TestPlugin1", func() (admission.Interface, error) {
		return testPlugin1, nil
	})

	// only initialize TestPlugin1
	_, err := p.NewFromPlugins([]string{"TestPlugin1", "TestPluginDoesNotExist"}, initializer.New(fake.NewSimpleClientset(), nil, nil, nil))
	if err == nil {
		t.Errorf("expected an error but got none")
	}
	if testPlugin1.kc == nil {
		t.Errorf("expected TestPlugin1 to be initialized")
	}
}

func TestPlugins_FailsIfPluginFailsToBuild(t *testing.T) {
	scheme := runtime.NewScheme()
	p := admission.NewPlugins(scheme)

	testPlugin1 := &testPlugin{}
	p.Register("TestPlugin1", func() (admission.Interface, error) {
		return testPlugin1, fmt.Errorf("an early error occurred")
	})

	// only initialize TestPlugin1
	_, err := p.NewFromPlugins([]string{"TestPlugin1"}, initializer.New(fake.NewSimpleClientset(), nil, nil, nil))
	if err == nil {
		t.Errorf("expected an error but got none")
	}
	if testPlugin1.kc != nil {
		t.Errorf("expected TestPlugin1 to not be initialized")
	}
}

type testPlugin struct {
	kc      kubernetes.Interface
	initErr error
}

var _ admission.Interface = &testPlugin{}
var _ initializer.WantsExternalKubeClientSet = &testPlugin{}

func (t *testPlugin) Handles(_ admissionv1.Operation) bool {
	return true
}

func (t *testPlugin) SetExternalKubeClientSet(k kubernetes.Interface) {
	t.kc = k
}

func (t *testPlugin) ValidateInitialization() error {
	return t.initErr
}
