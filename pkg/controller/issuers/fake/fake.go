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

package fake

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

type FakeIssuer struct {
	setupfn      func(context.Context, cmapi.GenericIssuer) error
	implementsfn func(cmapi.GenericIssuer) bool
	referencesfn func(cmapi.GenericIssuer, *corev1.Secret) bool
}

func New() *FakeIssuer {
	return &FakeIssuer{
		setupfn: func(context.Context, cmapi.GenericIssuer) error {
			return nil
		},
		implementsfn: func(cmapi.GenericIssuer) bool {
			return true
		},
		referencesfn: func(cmapi.GenericIssuer, *corev1.Secret) bool {
			return true
		},
	}
}

func (f *FakeIssuer) WithReferences(fn func(cmapi.GenericIssuer, *corev1.Secret) bool) *FakeIssuer {
	f.referencesfn = fn
	return f
}

func (f *FakeIssuer) WithImplements(fn func(cmapi.GenericIssuer) bool) *FakeIssuer {
	f.implementsfn = fn
	return f
}

func (f *FakeIssuer) WithSetup(fn func(context.Context, cmapi.GenericIssuer) error) *FakeIssuer {
	f.setupfn = fn
	return f
}

func (f *FakeIssuer) Setup(ctx context.Context, iss cmapi.GenericIssuer) error {
	return f.setupfn(ctx, iss)
}

func (f *FakeIssuer) Implements(iss cmapi.GenericIssuer) bool {
	return f.implementsfn(iss)
}

func (f *FakeIssuer) ReferencesSecret(iss cmapi.GenericIssuer, sec *corev1.Secret) bool {
	return f.ReferencesSecret(iss, sec)
}
