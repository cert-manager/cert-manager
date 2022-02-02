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

package fake

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	issuerpkg "github.com/cert-manager/cert-manager/pkg/issuer"
)

type Helper struct {
	GetGenericIssuerFunc func(ref cmmeta.ObjectReference, ns string) (cmapi.GenericIssuer, error)
}

var _ issuerpkg.Helper = &Helper{}

func (f *Helper) GetGenericIssuer(ref cmmeta.ObjectReference, ns string) (cmapi.GenericIssuer, error) {
	return f.GetGenericIssuerFunc(ref, ns)
}
