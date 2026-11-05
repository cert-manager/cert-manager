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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func Test_EffectiveDeletionPolicy(t *testing.T) {
	tests := map[string]struct {
		fieldValue    cmapi.CertificateDeletionPolicy
		defaultPolicy cmapi.CertificateDeletionPolicy
		expPolicy     cmapi.CertificateDeletionPolicy
		expSource     string
	}{
		"unset field inherits an Orphan default": {
			fieldValue: "", defaultPolicy: cmapi.CertificateDeletionPolicyOrphan,
			expPolicy: cmapi.CertificateDeletionPolicyOrphan, expSource: "spec.deletionPolicy unset, controller default Orphan",
		},
		"unset field inherits a Delete default": {
			fieldValue: "", defaultPolicy: cmapi.CertificateDeletionPolicyDelete,
			expPolicy: cmapi.CertificateDeletionPolicyDelete, expSource: "spec.deletionPolicy unset, controller default Delete",
		},
		"unset field and empty default means Orphan": {
			fieldValue: "", defaultPolicy: "",
			expPolicy: cmapi.CertificateDeletionPolicyOrphan, expSource: "spec.deletionPolicy unset, controller default Orphan",
		},
		"Delete field wins over an Orphan default": {
			fieldValue: cmapi.CertificateDeletionPolicyDelete, defaultPolicy: cmapi.CertificateDeletionPolicyOrphan,
			expPolicy: cmapi.CertificateDeletionPolicyDelete, expSource: "spec.deletionPolicy=Delete",
		},
		"Orphan field wins over a Delete default": {
			fieldValue: cmapi.CertificateDeletionPolicyOrphan, defaultPolicy: cmapi.CertificateDeletionPolicyDelete,
			expPolicy: cmapi.CertificateDeletionPolicyOrphan, expSource: "spec.deletionPolicy=Orphan",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			crt := gen.Certificate("test", gen.SetCertificateDeletionPolicy(test.fieldValue))
			gotPolicy, gotSource := EffectiveDeletionPolicy(crt, test.defaultPolicy)
			assert.Equal(t, test.expPolicy, gotPolicy)
			assert.Equal(t, test.expSource, gotSource)
		})
	}
}

func Test_SecretOwnerReferenceExpected(t *testing.T) {
	secretAnnotatedWith := func(owner string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{cmapi.CertificateNameKey: owner},
		}}
	}

	tests := map[string]struct {
		fieldValue    cmapi.CertificateDeletionPolicy
		defaultPolicy cmapi.CertificateDeletionPolicy
		secret        *corev1.Secret
		expExpected   bool
		expSource     string
	}{
		"unset field with Orphan default expects no owner reference": {
			defaultPolicy: cmapi.CertificateDeletionPolicyOrphan, secret: secretAnnotatedWith("test"),
			expExpected: false, expSource: "spec.deletionPolicy unset, controller default Orphan",
		},
		"unset field with Delete default expects an owner reference": {
			defaultPolicy: cmapi.CertificateDeletionPolicyDelete, secret: secretAnnotatedWith("test"),
			expExpected: true, expSource: "spec.deletionPolicy unset, controller default Delete",
		},
		"Orphan field expects no owner reference even with Delete default": {
			fieldValue: cmapi.CertificateDeletionPolicyOrphan, defaultPolicy: cmapi.CertificateDeletionPolicyDelete, secret: secretAnnotatedWith("test"),
			expExpected: false, expSource: "spec.deletionPolicy=Orphan",
		},
		"Delete field expects an owner reference on the Secret it owns": {
			fieldValue: cmapi.CertificateDeletionPolicyDelete, defaultPolicy: cmapi.CertificateDeletionPolicyOrphan, secret: secretAnnotatedWith("test"),
			expExpected: true, expSource: "spec.deletionPolicy=Delete",
		},
		"Delete field expects an owner reference on a Secret that does not exist yet": {
			fieldValue: cmapi.CertificateDeletionPolicyDelete, secret: nil,
			expExpected: true, expSource: "spec.deletionPolicy=Delete",
		},
		"Delete field expects an owner reference on a Secret without the annotation": {
			fieldValue: cmapi.CertificateDeletionPolicyDelete, secret: &corev1.Secret{},
			expExpected: true, expSource: "spec.deletionPolicy=Delete",
		},
		"Delete field expects an owner reference on a Secret with an empty annotation": {
			fieldValue: cmapi.CertificateDeletionPolicyDelete, secret: secretAnnotatedWith(""),
			expExpected: true, expSource: "spec.deletionPolicy=Delete",
		},
		"Delete field never expects an owner reference on a Secret owned by another Certificate": {
			fieldValue: cmapi.CertificateDeletionPolicyDelete, secret: secretAnnotatedWith("other"),
			expExpected: false, expSource: `Secret is owned by Certificate "other" according to its cert-manager.io/certificate-name annotation`,
		},
		"Delete default never expects an owner reference on a Secret owned by another Certificate": {
			defaultPolicy: cmapi.CertificateDeletionPolicyDelete, secret: secretAnnotatedWith("other"),
			expExpected: false, expSource: `Secret is owned by Certificate "other" according to its cert-manager.io/certificate-name annotation`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			crt := gen.Certificate("test", gen.SetCertificateDeletionPolicy(test.fieldValue))
			gotExpected, gotSource := SecretOwnerReferenceExpected(crt, test.secret, test.defaultPolicy)
			assert.Equal(t, test.expExpected, gotExpected)
			assert.Equal(t, test.expSource, gotSource)
		})
	}
}
