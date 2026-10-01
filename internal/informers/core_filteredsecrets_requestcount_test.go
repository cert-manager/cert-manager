/*
Copyright 2026 The cert-manager Authors.

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
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/metadata/metadatalister"
)

// Test_secretNamespaceLister_List_requestCount pins the number of live
// apiserver requests that a List makes. A Secret found only in the metadata
// cache is not usable as a corev1.Secret, so it has to be fetched live; a
// Secret that is already in the typed cache must never be fetched
// individually. #9347 records how every metadata-cache match used to cost
// one live GET each — one API request per Secret in the namespace, on every
// call — until List was changed to fall back to a single live LIST for all
// metadata-cache matches: zero live requests when the selector matches only
// typed-cache Secrets, one live LIST otherwise, regardless of how many
// Secrets the namespace holds.
func Test_secretNamespaceLister_List_requestCount(t *testing.T) {
	var (
		someData = []byte("foobar")

		secretLive = &corev1.Secret{
			// not in the typed cache: only reachable via the apiserver
			ObjectMeta: metav1.ObjectMeta{Name: "live", Namespace: "foo"},
			Data:       map[string][]byte{"someKey": someData},
		}
		secretLiveMeta = &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Name: "live", Namespace: "foo"},
		}

		secretLive2 = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "live-2", Namespace: "foo"},
			Data:       map[string][]byte{"someKey": someData},
		}
		secretLive2Meta = &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Name: "live-2", Namespace: "foo"},
		}

		secretTyped = &corev1.Secret{
			// the apiserver copy of a Secret that is also in the typed cache
			ObjectMeta: metav1.ObjectMeta{Name: "typed", Namespace: "foo"},
			Data:       map[string][]byte{"someKey": someData},
		}
		secretTypedMeta = &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Name: "typed", Namespace: "foo"},
		}

		// Returned by the live LIST but never listed by the metadata
		// cache, so the metadataSecretsSet filter has to drop it.
		secretNotInMetadataCache = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "foo"},
			Data:       map[string][]byte{"someKey": someData},
		}
		// In the metadata cache, whose entries have their labels
		// stripped, but carrying foo=bar live, so a `foo!=bar`
		// selector rejects it. On master the live Secret came back
		// regardless of its labels.
		secretRejectedBySelector = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "rejected",
				Namespace: "foo",
				Labels:    map[string]string{"foo": "bar"},
			},
			Data: map[string][]byte{"someKey": someData},
		}
		secretRejectedMeta = &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Name: "rejected", Namespace: "foo"},
		}
	)

	// listResponse is the SecretList the scenario's fake handed the
	// lister, kept so a result can be checked for aliasing it.
	var listResponse *corev1.SecretList

	tests := map[string]struct {
		typedLister           corev1listers.SecretLister
		partialMetadataLister metadatalister.Lister
		typedClient           typedcorev1.SecretsGetter
		// selector defaults to labels.Everything() when nil.
		selector labels.Selector

		wantLiveGets  int32
		wantLiveLists int32
		// wantListSelectors pins the LabelSelector sent on each live
		// LIST, in order. The selector has to reach the apiserver:
		// an empty ListOptions is a quorum read of every Secret in
		// the namespace with full data, only for the client to throw
		// most of it away.
		wantListSelectors []string
		// wantNoAliasing requires each result to be a copy rather than
		// a pointer into the LIST response, so holding one Secret does
		// not keep every Secret in the namespace reachable.
		wantNoAliasing bool
		want           []*corev1.Secret
	}{
		"Secrets the metadata cache never listed, and ones the selector rejects, are both dropped": {
			typedLister: &FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: &FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{secretLiveMeta, secretRejectedMeta}, nil
				},
			},
			typedClient: &FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return nil, errors.New("per-Secret GETs must not be used")
						},
						FakeList: func(context.Context, metav1.ListOptions) (*corev1.SecretList, error) {
							listResponse = &corev1.SecretList{
								Items: []corev1.Secret{*secretLive, *secretNotInMetadataCache, *secretRejectedBySelector},
							}
							return listResponse, nil
						},
					}
				},
			},
			selector:          notFooBarSelector(t),
			wantLiveLists:     1,
			wantListSelectors: []string{"foo!=bar"},
			// secretNotInMetadataCache was never listed by the metadata
			// cache, and secretRejectedBySelector carries foo=bar, which
			// `foo!=bar` rejects. Only secretLive survives.
			want: []*corev1.Secret{secretLive},
		},
		"the caller's selector reaches the apiserver, and the results are copies": {
			typedLister: &FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: &FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{secretLiveMeta, secretLive2Meta}, nil
				},
			},
			typedClient: &FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return nil, errors.New("per-Secret GETs must not be used")
						},
						FakeList: func(context.Context, metav1.ListOptions) (*corev1.SecretList, error) {
							listResponse = &corev1.SecretList{Items: []corev1.Secret{*secretLive, *secretLive2}}
							return listResponse, nil
						},
					}
				},
			},
			selector:          notFooBarSelector(t),
			wantLiveLists:     1,
			wantListSelectors: []string{"foo!=bar"},
			wantNoAliasing:    true,
			want:              []*corev1.Secret{secretLive, secretLive2},
		},
		"no matches in either cache cost no live requests": {
			typedLister: &FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: &FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return nil, nil
				},
			},
		},
		"matches served from the typed cache alone cost no live requests": {
			typedLister: &FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return []*corev1.Secret{secretTyped}, nil
				},
			},
			partialMetadataLister: &FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return nil, nil
				},
			},
			want: []*corev1.Secret{secretTyped},
		},
		"a Secret found only in the metadata cache costs exactly one live LIST": {
			typedLister: &FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: &FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{secretLiveMeta}, nil
				},
			},
			typedClient: &FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return nil, errors.New("per-Secret GETs must not be used")
						},
						FakeList: func(context.Context, metav1.ListOptions) (*corev1.SecretList, error) {
							return &corev1.SecretList{Items: []corev1.Secret{*secretLive}}, nil
						},
					}
				},
			},
			wantLiveLists:     1,
			wantListSelectors: []string{""},
			want:              []*corev1.Secret{secretLive},
		},
		"two metadata-only Secrets cost one live LIST, not one live GET per Secret": {
			typedLister: &FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return nil, nil
				},
			},
			partialMetadataLister: &FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{secretLiveMeta, secretLive2Meta}, nil
				},
			},
			typedClient: &FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return nil, errors.New("per-Secret GETs must not be used")
						},
						FakeList: func(context.Context, metav1.ListOptions) (*corev1.SecretList, error) {
							return &corev1.SecretList{
								Items: []corev1.Secret{*secretLive, *secretLive2},
							}, nil
						},
					}
				},
			},
			wantLiveLists:     1,
			wantListSelectors: []string{""},
			want:              []*corev1.Secret{secretLive, secretLive2},
		},
		"a duplicate is resolved from the same LIST, with the apiserver copy winning": {
			typedLister: &FakeSecretLister{
				FakeList: func(labels.Selector) ([]*corev1.Secret, error) {
					return []*corev1.Secret{{
						ObjectMeta: metav1.ObjectMeta{Name: "typed", Namespace: "foo"},
						Data:       map[string][]byte{"someOtherKey": someData},
					}}, nil
				},
			},
			partialMetadataLister: &FakeMetadataLister{
				FakeList: func(labels.Selector) ([]*metav1.PartialObjectMetadata, error) {
					return []*metav1.PartialObjectMetadata{secretTypedMeta}, nil
				},
			},
			typedClient: &FakeSecretsGetter{
				FakeSecrets: func(string) typedcorev1.SecretInterface {
					return FakeSecretInterface{
						FakeGet: func(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
							return nil, errors.New("per-Secret GETs must not be used")
						},
						FakeList: func(context.Context, metav1.ListOptions) (*corev1.SecretList, error) {
							return &corev1.SecretList{Items: []corev1.Secret{*secretTyped}}, nil
						},
					}
				},
			},
			wantLiveLists:     1,
			wantListSelectors: []string{""},
			want:              []*corev1.Secret{secretTyped},
		},
	}

	for name, scenario := range tests {
		t.Run(name, func(t *testing.T) {
			var liveGets, liveLists atomic.Int32
			var liveListSelectors []string

			// Wrap the scenario's fake client so every live Get/List the
			// lister makes is counted.
			if scenario.typedClient != nil {
				inner := scenario.typedClient
				scenario.typedClient = &countingSecretsGetter{
					inner:            inner,
					gets:             &liveGets,
					lists:            &liveLists,
					listLabelSelects: &liveListSelectors,
				}
			}

			snl := &secretNamespaceLister{
				namespace:             "foo",
				partialMetadataLister: scenario.partialMetadataLister,
				typedLister:           scenario.typedLister,
				typedClient:           scenario.typedClient,
				ctx:                   t.Context(),
			}
			selector := scenario.selector
			if selector == nil {
				selector = labels.Everything()
			}
			got, err := snl.List(selector)
			if err != nil {
				t.Fatalf("secretNamespaceLister.List() error = %v", err)
			}

			if gotGets, wantGets := liveGets.Load(), scenario.wantLiveGets; gotGets != wantGets {
				t.Errorf("live GETs = %d, want %d", gotGets, wantGets)
			}
			if gotLists, wantLists := liveLists.Load(), scenario.wantLiveLists; gotLists != wantLists {
				t.Errorf("live LISTs = %d, want %d", gotLists, wantLists)
			}
			assert.Equal(t, scenario.wantListSelectors, liveListSelectors, "LabelSelector sent on each live LIST")
			assert.ElementsMatch(t, got, scenario.want)
			if scenario.wantNoAliasing {
				// A pointer into the LIST response keeps every Secret in
				// the namespace, with data, reachable for as long as the
				// caller holds one result, so a write to a result must
				// not be visible in the response the fake handed us.
				for _, secret := range got {
					secret.Data["written-after-the-call"] = []byte("x")
					for idx := range listResponse.Items {
						if listResponse.Items[idx].Name != secret.Name {
							continue
						}
						if _, leaked := listResponse.Items[idx].Data["written-after-the-call"]; leaked {
							t.Errorf("Secret %q aliases the LIST response: writing to the result changed the response item", secret.Name)
						}
						delete(listResponse.Items[idx].Data, "written-after-the-call")
					}
				}
			}
		})
	}
}

// notFooBarSelector builds a `foo!=bar` selector: it matches a
// label-stripped metadata entry but rejects the live Secret that
// carries foo=bar.
func notFooBarSelector(t *testing.T) labels.Selector {
	t.Helper()
	req, err := labels.NewRequirement("foo", selection.NotEquals, []string{"bar"})
	if err != nil {
		t.Fatalf("building the selector: %v", err)
	}
	return labels.NewSelector().Add(*req)
}

// countingSecretsGetter counts the live Get/List calls made through it,
// delegating to the wrapped SecretsGetter.
type countingSecretsGetter struct {
	inner            typedcorev1.SecretsGetter
	gets             *atomic.Int32
	lists            *atomic.Int32
	listLabelSelects *[]string
}

func (c *countingSecretsGetter) Secrets(namespace string) typedcorev1.SecretInterface {
	return countingSecretInterface{
		SecretInterface:  c.inner.Secrets(namespace),
		gets:             c.gets,
		lists:            c.lists,
		listLabelSelects: c.listLabelSelects,
	}
}

// countingSecretInterface counts live Get/List calls, delegating everything
// else to the wrapped SecretInterface.
type countingSecretInterface struct {
	typedcorev1.SecretInterface
	gets             *atomic.Int32
	lists            *atomic.Int32
	listLabelSelects *[]string
}

func (c countingSecretInterface) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	c.gets.Add(1)
	return c.SecretInterface.Get(ctx, name, opts)
}

func (c countingSecretInterface) List(ctx context.Context, opts metav1.ListOptions) (*corev1.SecretList, error) {
	c.lists.Add(1)
	if c.listLabelSelects != nil {
		*c.listLabelSelects = append(*c.listLabelSelects, opts.LabelSelector)
	}
	return c.SecretInterface.List(ctx, opts)
}
