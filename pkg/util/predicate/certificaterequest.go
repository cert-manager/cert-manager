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
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// CertificateRequestRevision returns a predicate that used to filter
// CertificateRequest to only those with a given 'revision' number.
func CertificateRequestRevision(revision int) Func {
	return func(obj runtime.Object) bool {
		req := obj.(*cmapi.CertificateRequest)
		if req.Annotations == nil {
			return false
		}
		return req.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] == fmt.Sprintf("%d", revision)
	}
}
