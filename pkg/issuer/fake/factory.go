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
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	issuerpkg "github.com/cert-manager/cert-manager/pkg/issuer"
)

type Factory struct {
	IssuerForFunc func(iss v1.GenericIssuer) (issuerpkg.Interface, error)
}

var _ issuerpkg.Factory = &Factory{}

func (f *Factory) IssuerFor(iss v1.GenericIssuer) (issuerpkg.Interface, error) {
	return f.IssuerForFunc(iss)
}
