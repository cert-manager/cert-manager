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

// coreclients contains fakes for some of the types from
// k8s.io/client-go/kubernetes/typed/core/v1
package coreclients

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	applyconfigurationscorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

var _ typedcorev1.SecretsGetter = &FakeSecretsGetter{}

// FakeSecretsGetter can be used to mock typedcorev1.SecretsGetter in tests.
type FakeSecretsGetter struct {
	c *fakeSecretClient
}

type FakeSecretsGetterModifier func(*FakeSecretsGetter)

// NewFakeSecretsGetterFrom can be used to create a mock typedcorev1.SecretsGetter for tests.
// Example: NewFakeSecretsGetterFrom(NewFakeSecretsGetter(), SetFakeSecretsGetterCreate(<secret>, <error>)).
func NewFakeSecretsGetterFrom(f *FakeSecretsGetter, mods ...FakeSecretsGetterModifier) *FakeSecretsGetter {
	for _, mod := range mods {
		mod(f)
	}
	return f
}

func NewFakeSecretsGetter(mods ...FakeSecretsGetterModifier) *FakeSecretsGetter {
	return NewFakeSecretsGetterFrom(&FakeSecretsGetter{
		c: &fakeSecretClient{},
	}, mods...)
}

// SetFakeSecretsGetterCreate is a modifier that can be used to set secret and
// error that will be returned when
// FakeSecretsGetter(<namespace>).Create(<secret>, <opts>) is called.
func SetFakeSecretsGetterCreate(s *corev1.Secret, err error) FakeSecretsGetterModifier {
	return func(f *FakeSecretsGetter) {
		f.c.CreateFn = func() (*corev1.Secret, error) {
			return s, err
		}
	}
}

// SetFakeSecretsGetterGet is a modifier that can be used to set secret and
// error that will be returned when
// FakeSecretsGetter(<namespace>).Get(<context>,<uid>,<opts>) is called.
func SetFakeSecretsGetterGet(s *corev1.Secret, err error) FakeSecretsGetterModifier {
	return func(f *FakeSecretsGetter) {
		f.c.GetFn = func() (*corev1.Secret, error) {
			return s, err
		}
	}
}

// SetFakeSecretsGetterApplyFn is a function that can be used to inject code
// when the FakeSecretsGetter is Applied.
func SetFakeSecretsGetterApplyFn(fn ApplyFn) FakeSecretsGetterModifier {
	return func(f *FakeSecretsGetter) {
		f.c.ApplyFn = fn
	}
}

func (f *FakeSecretsGetter) Secrets(string) typedcorev1.SecretInterface {
	return f.c
}

type ApplyFn func(context.Context, *applyconfigurationscorev1.SecretApplyConfiguration, metav1.ApplyOptions) (*corev1.Secret, error)

type fakeSecretClient struct {
	CreateFn           func() (*corev1.Secret, error)
	UpdateFn           func() (*corev1.Secret, error)
	DeleteFn           func() error
	DeleteCollectionFn func() error
	GetFn              func() (*corev1.Secret, error)
	ListFn             func() (*corev1.SecretList, error)
	WatchFn            func() (watch.Interface, error)
	PatchFn            func() (*corev1.Secret, error)
	ApplyFn            ApplyFn
	// Currently there is no need to mock this interface
	typedcorev1.SecretExpansion
}

func (f *fakeSecretClient) Create(context.Context, *corev1.Secret, metav1.CreateOptions) (*corev1.Secret, error) {
	return f.CreateFn()
}

func (f *fakeSecretClient) Update(context.Context, *corev1.Secret, metav1.UpdateOptions) (*corev1.Secret, error) {
	return f.UpdateFn()
}

func (f *fakeSecretClient) Delete(context.Context, string, metav1.DeleteOptions) error {
	return f.DeleteFn()
}

func (f *fakeSecretClient) DeleteCollection(context.Context, metav1.DeleteOptions, metav1.ListOptions) error {
	return f.DeleteCollectionFn()
}

func (f *fakeSecretClient) Get(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
	return f.GetFn()
}

func (f *fakeSecretClient) List(context.Context, metav1.ListOptions) (*corev1.SecretList, error) {
	return f.ListFn()
}

func (f *fakeSecretClient) Watch(context.Context, metav1.ListOptions) (watch.Interface, error) {
	return f.WatchFn()
}

func (f *fakeSecretClient) Patch(context.Context, string, types.PatchType, []byte, metav1.PatchOptions, ...string) (*corev1.Secret, error) {
	return f.PatchFn()
}

func (f *fakeSecretClient) Apply(ctx context.Context, cnf *applyconfigurationscorev1.SecretApplyConfiguration, opts metav1.ApplyOptions) (*corev1.Secret, error) {
	return f.ApplyFn(ctx, cnf, opts)
}
