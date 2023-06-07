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

package predicate

import (
	"k8s.io/apimachinery/pkg/runtime"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// CertificateSecretName returns a predicate that used to filter Certificates
// to only those with the given 'spec.secretName'.
func CertificateSecretName(name string) Func {
	return func(obj runtime.Object) bool {
		crt := obj.(*cmapi.Certificate)
		return crt.Spec.SecretName == name
	}
}

// CertificateNextPrivateKeySecretName returns a predicate that used to filter Certificates
// to only those with the given 'status.nextPrivateKeySecretName'.
// It is not possible to select Certificates with a 'nil' secret name using
// this predicate function.
func CertificateNextPrivateKeySecretName(name string) Func {
	return func(obj runtime.Object) bool {
		crt := obj.(*cmapi.Certificate)
		if crt.Status.NextPrivateKeySecretName == nil {
			return false
		}
		return *crt.Status.NextPrivateKeySecretName == name
	}
}
