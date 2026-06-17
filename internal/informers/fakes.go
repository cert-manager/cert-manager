/*
Copyright 2023 The cert-manager Authors.

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

package informers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	applyconfigcorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/metadata/metadatalister"
)

// FakeSecretLister is a fake of SecretLister
// https://github.com/kubernetes/client-go/blob/0382bf0f53b2294d4ac448203718f0ba774a477d/listers/core/v1/secret.go#L28-L37
type FakeSecretLister struct {
	NamespaceLister FakeSecretNamespaceLister
	FakeList        func(labels.Selector) ([]*corev1.Secret, error)
}

func (fsl FakeSecretLister) List(selector labels.Selector) ([]*corev1.Secret, error) {
	return fsl.FakeList(selector)
}

func (fsl FakeSecretLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	return fsl.NamespaceLister
}

// FakeSecretNamespaceLister is a fake of SecretNamespaceLister
// https://github.com/kubernetes/client-go/blob/0382bf0f53b2294d4ac448203718f0ba774a477d/listers/core/v1/secret.go#L62-L72.
type FakeSecretNamespaceLister struct {
	FakeList func(labels.Selector) ([]*corev1.Secret, error)
	FakeGet  func(string) (*corev1.Secret, error)
}

func (fsnl FakeSecretNamespaceLister) List(selector labels.Selector) ([]*corev1.Secret, error) {
	return fsnl.FakeList(selector)
}

func (fsnl FakeSecretNamespaceLister) Get(name string) (*corev1.Secret, error) {
	return fsnl.FakeGet(name)
}

// FakeMetadataLister is a fake of metadata Lister
// https://github.com/kubernetes/client-go/blob/0382bf0f53b2294d4ac448203718f0ba774a477d/metadata/metadatalister/interface.go#L24-L32
type FakeMetadataLister struct {
	FakeList        func(labels.Selector) ([]*metav1.PartialObjectMetadata, error)
	FakeGet         func(string) (*metav1.PartialObjectMetadata, error)
	NamespaceLister metadatalister.NamespaceLister
}

func (fml FakeMetadataLister) List(selector labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
	return fml.FakeList(selector)
}

func (fml FakeMetadataLister) Get(name string) (*metav1.PartialObjectMetadata, error) {
	return fml.FakeGet(name)
}

func (fml FakeMetadataLister) Namespace(string) metadatalister.NamespaceLister {
	return fml.NamespaceLister
}

// FakeMetadataNamespaceLister is a fake of metadata NamespaceLister
// https://github.com/kubernetes/client-go/blob/0382bf0f53b2294d4ac448203718f0ba774a477d/metadata/metadatalister/interface.go#L34-L40
type FakeMetadataNamespaceLister struct {
	FakeList func(labels.Selector) ([]*metav1.PartialObjectMetadata, error)
	FakeGet  func(string) (*metav1.PartialObjectMetadata, error)
}

func (fmnl FakeMetadataNamespaceLister) List(selector labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
	return fmnl.FakeList(selector)
}

func (fmnl FakeMetadataNamespaceLister) Get(name string) (*metav1.PartialObjectMetadata, error) {
	return fmnl.FakeGet(name)
}

// FakeSecretsGetter is a fake of corev1 SecretsGetter
// https://github.com/kubernetes/client-go/blob/0382bf0f53b2294d4ac448203718f0ba774a477d/kubernetes/typed/core/v1/secret.go#L33-L37
type FakeSecretsGetter struct {
	FakeSecrets func(string) typedcorev1.SecretInterface
}

func (fsg FakeSecretsGetter) Secrets(namespace string) typedcorev1.SecretInterface {
	return fsg.FakeSecrets(namespace)
}

// FakeSecretInterface is a fake of corev1 SecretInterface
// https://github.com/kubernetes/client-go/blob/0382bf0f53b2294d4ac448203718f0ba774a477d/kubernetes/typed/core/v1/secret.go#L39-L50
type FakeSecretInterface struct {
	FakeGet  func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error)
	FakeList func(context.Context, metav1.ListOptions) (*corev1.SecretList, error)
}

func (fsi FakeSecretInterface) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	return fsi.FakeGet(ctx, name, opts)
}
func (fsi FakeSecretInterface) List(ctx context.Context, opts metav1.ListOptions) (*corev1.SecretList, error) {
	return fsi.FakeList(ctx, opts)
}

func (fsi FakeSecretInterface) Create(ctx context.Context, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error) {
	panic("not implemented")
}

func (fsi FakeSecretInterface) Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error) {
	panic("not implemented")
}
func (fsi FakeSecretInterface) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	panic("not implemented")
}
func (fsi FakeSecretInterface) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	panic("not implemented")
}
func (fsi FakeSecretInterface) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	panic("not implemented")
}
func (fsi FakeSecretInterface) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *corev1.Secret, err error) {
	panic("not implemented")
}
func (fsi FakeSecretInterface) Apply(ctx context.Context, secret *applyconfigcorev1.SecretApplyConfiguration, opts metav1.ApplyOptions) (result *corev1.Secret, err error) {
	panic("not implemented")
}
