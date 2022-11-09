/*
Copyright 2022 The cert-manager Authors.

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

package certificates

import (
	"context"
	"sort"

	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
)

// DuplicateCertificateSecretNames returns a list of Certificate names which
// have the same Secret name set as the given Certificate.
func DuplicateCertificateSecretNames(ctx context.Context, lister cmlisters.CertificateLister, crt *cmapi.Certificate) ([]string, error) {
	crts, err := lister.Certificates(crt.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	var duplicates []string
	for _, namespaceCrt := range crts {
		// Skip the Certificate we are currently processing.
		if namespaceCrt.Name != crt.Name &&
			// Check if it has the same Secret.
			namespaceCrt.Spec.SecretName == crt.Spec.SecretName {
			// If it does, mark the Certificate as having a duplicate Secret.
			duplicates = append(duplicates, namespaceCrt.Name)
		}
	}

	sort.Strings(duplicates)

	return duplicates, nil
}
