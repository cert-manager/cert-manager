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
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/metadata/metadatalister"
)

func Test_secretNamespaceLister_Get(t *testing.T) {

	var (
		data       = []byte("foo")
		testSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "foo",
			},
			Data: map[string][]byte{"foo": data},
		}
	)
	tests := map[string]struct {
		namespace             string
		name                  string
		partialMetadataLister metadatalister.Lister
		typedLister           corev1listers.SecretLister
		typedClient           typedcorev1.SecretsGetter
		want                  *corev1.Secret
		wantErr               bool
	}{
		"if querying typed cache returns an error that is not 'not found' error, return the error": {
			namespace: "foo",
			name:      "foo",
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeGet: func(string) (*corev1.Secret, error) {
						return nil, errors.New("some error")
					},
				},
			},
			wantErr: true,
		},
		"if querying metadata cache returns an error that is not a 'not found' error, return the error": {
			namespace: "foo",
			name:      "foo",
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeGet: func(string) (*corev1.Secret, error) {
						return nil, nil
					},
				},
			},
			partialMetadataLister: FakeMetadataLister{
				NamespaceLister: FakeMetadataNamespaceLister{
					FakeGet: func(string) (*metav1.PartialObjectMetadata, error) {
						return nil, errors.New("some error")
					},
				},
			},
			wantErr: true,
		},
		"if Secret found in typed cache, return it from there": {
			namespace: "foo",
			name:      "foo",
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeGet: func(string) (*corev1.Secret, error) {
						return testSecret, nil
					},
				},
			},
			partialMetadataLister: FakeMetadataLister{
				NamespaceLister: FakeMetadataNamespaceLister{
					FakeGet: func(string) (*metav1.PartialObjectMetadata, error) {
						return nil, apierrors.NewNotFound(schema.GroupResource{}, "foo")
					},
				},
			},
			want: testSecret,
		},
		"if Secret found in metadata cache, return it from kube apiserver": {
			namespace: "foo",
			name:      "foo",
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeGet: func(string) (*corev1.Secret, error) {
						return nil, apierrors.NewNotFound(schema.GroupResource{}, "foo")
					},
				},
			},
			partialMetadataLister: FakeMetadataLister{
				NamespaceLister: FakeMetadataNamespaceLister{
					FakeGet: func(string) (*metav1.PartialObjectMetadata, error) {
						return &metav1.PartialObjectMetadata{}, nil
					},
				},
			},
			typedClient: FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return testSecret, nil
						},
					}
				},
			},
			want: testSecret,
		},
		"if Secret found in both caches, return it from kube apiserver": {
			namespace: "foo",
			name:      "foo",
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeGet: func(string) (*corev1.Secret, error) {
						return &corev1.Secret{}, nil
					},
				},
			},
			partialMetadataLister: FakeMetadataLister{
				NamespaceLister: FakeMetadataNamespaceLister{
					FakeGet: func(string) (*metav1.PartialObjectMetadata, error) {
						return &metav1.PartialObjectMetadata{}, nil
					},
				},
			},
			typedClient: FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return testSecret, nil
						},
					}
				},
			},
			want: testSecret,
		},
		"if Secret found in metadata cache, but querying kube apiserver errors, return the error": {
			namespace: "foo",
			name:      "foo",
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeGet: func(string) (*corev1.Secret, error) {
						return nil, apierrors.NewNotFound(schema.GroupResource{}, "foo")
					},
				},
			},
			partialMetadataLister: FakeMetadataLister{
				NamespaceLister: FakeMetadataNamespaceLister{
					FakeGet: func(string) (*metav1.PartialObjectMetadata, error) {
						return &metav1.PartialObjectMetadata{}, nil
					},
				},
			},
			typedClient: FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return nil, errors.New("some error")
						},
					}
				},
			},
			wantErr: true,
		},
		"if Secret found not found in either cache return not found error": {
			namespace: "foo",
			name:      "foo",
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeGet: func(string) (*corev1.Secret, error) {
						return nil, apierrors.NewNotFound(schema.GroupResource{}, "foo")
					},
				},
			},
			partialMetadataLister: FakeMetadataLister{
				NamespaceLister: FakeMetadataNamespaceLister{
					FakeGet: func(string) (*metav1.PartialObjectMetadata, error) {
						return &metav1.PartialObjectMetadata{}, apierrors.NewNotFound(schema.GroupResource{}, "foo")
					},
				},
			},
			typedClient: FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return nil, errors.New("some error")
						},
					}
				},
			},
			wantErr: true,
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			snl := &secretNamespaceLister{
				namespace:             scenario.namespace,
				partialMetadataLister: scenario.partialMetadataLister,
				typedLister:           scenario.typedLister,
				typedClient:           scenario.typedClient,
				ctx:                   context.Background(),
			}
			got, err := snl.Get(name)
			if (err != nil) != scenario.wantErr {
				t.Errorf("secretNamespaceLister.Get() error = %v, wantErr %v", err, scenario.wantErr)
				return
			}
			if !reflect.DeepEqual(got, scenario.want) {
				t.Errorf("secretNamespaceLister.Get() = %v, want %v", got, scenario.want)
			}
		})
	}
}

func Test_secretNamespaceLister_List(t *testing.T) {

	var (
		someData     = []byte("foobar")
		someSelector = labels.Everything()
		secretFoo    = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "foo",
			},
			Data: map[string][]byte{"someKey": someData},
		}
		secretFoo2 = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "foo",
			},
			Data: map[string][]byte{"someOtherKey": someData},
		}
		secretBar = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bar",
				Namespace: "bar",
			},
			Data: map[string][]byte{"someKey": someData},
		}
		secretFooMeta = metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "foo",
			},
		}
	)
	tests := map[string]struct {
		namespace             string
		partialMetadataLister metadatalister.Lister
		typedLister           corev1listers.SecretLister
		typedClient           typedcorev1.SecretsGetter
		want                  []*corev1.Secret
		wantErr               bool
	}{
		"if listing Secrets from typed cache errors out then return the error": {

			namespace: "foo",
			typedLister: FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, errors.New("some error")
				},
			},
			wantErr: true,
		},
		"if listing Secrets from metadata cache errors out then return the error": {

			namespace: "foo",
			typedLister: FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return nil, errors.New("some error")
				},
			},
			wantErr: true,
		},
		"if no Secrets are found within either cache, don't return any": {

			namespace: "foo",
			typedLister: FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return nil, nil
				},
			},
			want: make([]*corev1.Secret, 0),
		},
		"if some Secrets are found in typed cache, return those": {

			namespace: "foo",
			typedLister: FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return []*corev1.Secret{&secretBar, &secretFoo}, nil
				},
			},
			partialMetadataLister: FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return nil, nil
				},
			},
			want: []*corev1.Secret{&secretBar, &secretFoo},
		},
		"if a Secret is found in metadata only cache, return it from kube apiserver": {

			namespace: "foo",
			typedLister: FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{&secretFooMeta}, nil
				},
			},
			typedClient: FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return &secretFoo, nil
						},
					}
				},
			},
			want: []*corev1.Secret{&secretFoo},
		},
		"if matching non-duplicate Secrets are found in both caches, return them": {

			namespace: "foo",
			typedLister: FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return []*corev1.Secret{&secretBar}, nil
				},
			},
			partialMetadataLister: FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{&secretFooMeta}, nil
				},
			},
			typedClient: FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return &secretFoo, nil
						},
					}
				},
			},
			want: []*corev1.Secret{&secretFoo, &secretBar},
		},
		"if matching Secrets are found in both caches with some duplicates, then returned the duplicates from kube apiserver": {

			namespace: "foo",
			typedLister: FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return []*corev1.Secret{&secretFoo2}, nil
				},
			},
			partialMetadataLister: FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{&secretFooMeta}, nil
				},
			},
			typedClient: FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return &secretFoo, nil
						},
					}
				},
			},
			want: []*corev1.Secret{&secretFoo},
		},
		"if a Secret is found in metadata only cache, but querying kube apiserver errors, return the error": {

			namespace: "foo",
			typedLister: FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{&secretFooMeta}, nil
				},
			},
			typedClient: FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return nil, errors.New("some error")
						},
					}
				},
			},
			wantErr: true,
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			snl := &secretNamespaceLister{
				namespace:             scenario.namespace,
				partialMetadataLister: scenario.partialMetadataLister,
				typedLister:           scenario.typedLister,
				typedClient:           scenario.typedClient,
				ctx:                   context.Background(),
			}
			got, err := snl.List(someSelector)
			if (err != nil) != scenario.wantErr {
				t.Errorf("secretNamespaceLister.List() error = %v, wantErr %v", err, scenario.wantErr)
				return
			}
			assert.ElementsMatch(t, got, scenario.want)
		})
	}
}
