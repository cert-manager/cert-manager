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

package fake

import (
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	issuerpkg "github.com/jetstack/cert-manager/pkg/issuer"
)

type Factory struct {
	IssuerForFunc func(iss v1alpha1.GenericIssuer) (issuerpkg.Interface, error)
}

var _ issuerpkg.Factory = &Factory{}

func (f *Factory) IssuerFor(iss v1alpha1.GenericIssuer) (issuerpkg.Interface, error) {
	return f.IssuerForFunc(iss)
}
