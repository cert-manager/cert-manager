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
	"k8s.io/client-go/tools/cache"

	"github.com/cert-manager/cert-manager/internal/test/testutil"
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
				ctx:                   t.Context(),
			}
			got, err := snl.Get(name)
			if (err != nil) != scenario.wantErr {
				t.Errorf("secretNamespaceLister.Get() error = %v, wantErr %v", err, scenario.wantErr)
				return
			}
			testutil.AssertEqual(t, scenario.want, got)
		})
	}
}

func Test_secretNamespaceLister_List(t *testing.T) {

	mustParse := func(s string) labels.Selector {
		selector, err := labels.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return selector
	}

	// FakeSecretLister.Secrets ignores its namespace, so scoping needs a real indexer.
	indexedSecretLister := func(secrets ...*corev1.Secret) corev1listers.SecretLister {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		for _, secret := range secrets {
			if err := indexer.Add(secret); err != nil {
				t.Fatal(err)
			}
		}
		return corev1listers.NewSecretLister(indexer)
	}

	var (
		someData  = []byte("foobar")
		secretFoo = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "foo",
			},
			Data: map[string][]byte{"someKey": someData},
		}
		secretNsA = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shared-name",
				Namespace: "ns-a",
				Labels:    map[string]string{"foo": "bar"},
			},
			Data: map[string][]byte{"someKey": someData},
		}
		secretNsB = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shared-name",
				Namespace: "ns-b",
				Labels:    map[string]string{"foo": "bar"},
			},
			Data: map[string][]byte{"someKey": someData},
		}
	)
	refuseToList := FakeSecretLister{
		NamespaceLister: FakeSecretNamespaceLister{
			FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
				t.Error("List reached the typed cache; the guard must refuse first")
				return nil, nil
			},
		},
	}
	tests := map[string]struct {
		namespace   string
		selector    labels.Selector
		typedLister corev1listers.SecretLister
		want        []*corev1.Secret
		wantErr     bool
	}{
		"if the selector matches everything, refuse to list": {
			namespace:   "foo",
			selector:    labels.Everything(),
			typedLister: refuseToList,
			wantErr:     true,
		},
		"if the selector only excludes a label value, refuse to list": {
			namespace:   "foo",
			selector:    mustParse("foo!=bar"),
			typedLister: refuseToList,
			wantErr:     true,
		},
		"if the selector pairs a label requirement with a negative requirement, list from the typed cache": {
			namespace: "foo",
			selector:  mustParse("foo in (a,b),!bar"),
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
						return []*corev1.Secret{&secretFoo}, nil
					},
				},
			},
			want: []*corev1.Secret{&secretFoo},
		},
		"if listing Secrets from typed cache errors out then return the error": {
			namespace: "foo",
			selector:  mustParse("foo=bar"),
			typedLister: FakeSecretLister{
				NamespaceLister: FakeSecretNamespaceLister{
					FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
						return nil, errors.New("some error")
					},
				},
			},
			wantErr: true,
		},
		"if matching Secrets exist in another namespace, list only this lister's namespace": {
			namespace:   "ns-a",
			selector:    mustParse("foo=bar"),
			typedLister: indexedSecretLister(&secretNsA, &secretNsB),
			want:        []*corev1.Secret{&secretNsA},
		},
	}
	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			snl := &secretNamespaceLister{
				namespace:   scenario.namespace,
				typedLister: scenario.typedLister,
			}
			got, err := snl.List(scenario.selector)
			if (err != nil) != scenario.wantErr {
				t.Errorf("secretNamespaceLister.List() error = %v, wantErr %v", err, scenario.wantErr)
				return
			}
			assert.ElementsMatch(t, got, scenario.want)
		})
	}
}

func Test_secretNamespaceLister_List_refusalWrapsErrUnlabeledSelector(t *testing.T) {
	snl := &secretNamespaceLister{namespace: "foo"}
	_, err := snl.List(labels.Everything())
	if !errors.Is(err, ErrUnlabeledSelector) {
		t.Errorf("secretNamespaceLister.List() error = %v, want it to wrap ErrUnlabeledSelector", err)
	}
}
