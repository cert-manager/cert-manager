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
	"slices"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
)

// We determine whether a Certificate owns its Secret in order to prevent a CertificateRequest
// creation runaway. We use an annotation on the Secret to determine whether it is owned by a
// Certificate. We do not use the ownerReferences field on the Secret because the owner reference
// will not be set if the `--enable-certificate-owner-ref` flag is not set.
//
// We determine if the passed Certificate owns its Secret as follows:
//  1. If the target Secret exists and it is annotated with the name of this
//     Certificate, then this Certificate is the owner.
//  2. If the target Secret exists and it is annotated with the name of another
//     Certificate that has the Secret as its secretRef, then that Certificate
//     is the owner instead.
//  3. If the target Secret exists and it is not annotated with the name of any
//     Certificate, or it is annotated with the name of a Certificate that does
//     not exist, or does not have the Secret as its secretRef, then the oldest
//     Certificate which references it will be assumed to be the future owner.
func CertificateOwnsSecret(
	ctx context.Context,
	certificateLister cmlisters.CertificateLister,
	secretLister internalinformers.SecretLister,
	crt *cmapi.Certificate,
) (bool, []string, error) {
	crts, err := certificateLister.Certificates(crt.Namespace).List(labels.Everything())
	if err != nil {
		return false, nil, err
	}

	var duplicateCrts []*cmapi.Certificate
	for _, namespaceCrt := range crts {
		// Check if it has the same Secret.
		if namespaceCrt.Spec.SecretName == crt.Spec.SecretName {
			// If it does, mark the Certificate as having a duplicate Secret.
			duplicateCrts = append(duplicateCrts, namespaceCrt)
		}
	}

	// If there are no duplicates, return early.
	if len(duplicateCrts) == 1 && duplicateCrts[0].Name == crt.Name {
		return true, nil, nil
	}

	sort.Slice(duplicateCrts, func(i, j int) bool {
		return crts[i].CreationTimestamp.Before(&crts[j].CreationTimestamp) ||
			crts[i].Name < crts[j].Name
	})

	duplicateNames := make([]string, len(duplicateCrts))
	for i, crt := range duplicateCrts {
		duplicateNames[i] = crt.Name
	}

	ownerCertificate := duplicateNames[0]

	// Fetch the Secret and determine if it is owned by any of the Certificates.
	secret, err := secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, nil, err
	} else if err == nil {
		if annotation, hasAnnotation := secret.GetAnnotations()[cmapi.CertificateNameKey]; hasAnnotation && slices.Contains(duplicateNames, annotation) {
			ownerCertificate = annotation
		}
	}

	// If the Secret does not exist, only the first Certificate in the list
	// is the owner of the Secret.
	return crt.Name == ownerCertificate, sliceWithoutValue(duplicateNames, crt.Name), nil
}

func sliceWithoutValue(slice []string, value string) []string {
	result := make([]string, 0, len(slice)-1)
	for _, v := range slice {
		if v != value {
			result = append(result, v)
		}
	}
	return result
}
