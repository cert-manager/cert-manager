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

package certificates

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// EffectiveDeletionPolicy returns the deletion policy that applies to crt,
// which is spec.deletionPolicy when it is set and defaultPolicy otherwise,
// together with a short description of where the value came from for log and
// event messages. An empty defaultPolicy means Orphan.
func EffectiveDeletionPolicy(crt *cmapi.Certificate, defaultPolicy cmapi.CertificateDeletionPolicy) (cmapi.CertificateDeletionPolicy, string) {
	if crt.Spec.DeletionPolicy != "" {
		return crt.Spec.DeletionPolicy, fmt.Sprintf("spec.deletionPolicy=%s", crt.Spec.DeletionPolicy)
	}
	if defaultPolicy == "" {
		defaultPolicy = cmapi.CertificateDeletionPolicyOrphan
	}
	return defaultPolicy, fmt.Sprintf("spec.deletionPolicy unset, controller default %s", defaultPolicy)
}

// SecretOwnerReferenceExpected reports whether secret must carry a controller
// reference to crt, and why.
//
// The reference is expected only when the effective deletion policy of crt is
// Delete and secret is the Secret crt owns. A Secret is owned by crt when its
// cert-manager.io/certificate-name annotation names crt, or when the
// annotation is absent: a Secret that is about to be created, or one written
// before cert-manager started annotating Secrets. A Secret annotated with
// another Certificate's name never receives crt's owner reference, whatever
// the policy says, so a Certificate that points at a Secret it does not own
// cannot have that Secret garbage collected.
func SecretOwnerReferenceExpected(crt *cmapi.Certificate, secret *corev1.Secret, defaultPolicy cmapi.CertificateDeletionPolicy) (bool, string) {
	policy, source := EffectiveDeletionPolicy(crt, defaultPolicy)
	if policy != cmapi.CertificateDeletionPolicyDelete {
		return false, source
	}
	if secret != nil {
		if owner, ok := secret.Annotations[cmapi.CertificateNameKey]; ok && owner != "" && owner != crt.Name {
			return false, fmt.Sprintf("Secret is owned by Certificate %q according to its %s annotation", owner, cmapi.CertificateNameKey)
		}
	}
	return true, source
}
