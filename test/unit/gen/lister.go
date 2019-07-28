/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package gen

import (
	corev1 "k8s.io/api/core/v1"
	clientcorev1 "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/controller/test/fake"
)

type FakeSecretListerModifier func(*fake.FakeSecretLister)
type FakeSecretNamespaceListerModifier func(*fake.FakeSecretNamespaceLister)

func FakeSecretLister(mods ...FakeSecretListerModifier) *fake.FakeSecretLister {
	s := fake.NewFakeSecretLister()
	for _, mod := range mods {
		mod(s)
	}
	return s
}

func FakeSecretListerFrom(s *fake.FakeSecretLister, mods ...FakeSecretListerModifier) *fake.FakeSecretLister {
	for _, mod := range mods {
		mod(s)
	}
	return s
}

func FakeSecretNamespaceLister(mods ...FakeSecretNamespaceListerModifier) *fake.FakeSecretNamespaceLister {
	s := fake.NewFakeSecretNamespaceLister()
	for _, mod := range mods {
		mod(s)
	}
	return s
}

func SetFakeSecretListerSecret(s func(namespace string) clientcorev1.SecretNamespaceLister) FakeSecretListerModifier {
	return func(f *fake.FakeSecretLister) {
		f.SecretsFn = s
	}
}

func SetFakeSecretNamespaceListerGet(sec *corev1.Secret, err error) FakeSecretListerModifier {
	return func(f *fake.FakeSecretLister) {
		f.SecretsFn = func(namespace string) clientcorev1.SecretNamespaceLister {
			return &fake.FakeSecretNamespaceLister{
				GetFn: func(name string) (*corev1.Secret, error) {
					return sec, err
				},
			}
		}
	}
}
