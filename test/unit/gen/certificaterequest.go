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

package gen

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type CertificateRequestModifier func(*v1alpha1.CertificateRequest)

func CertificateRequest(name string, mods ...CertificateRequestModifier) *v1alpha1.CertificateRequest {
	c := &v1alpha1.CertificateRequest{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func CertificateRequestFrom(cr *v1alpha1.CertificateRequest, mods ...CertificateRequestModifier) *v1alpha1.CertificateRequest {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

// SetIssuer sets the CertificateRequest.spec.issuerRef field
func SetCertificateRequestIssuer(o v1alpha1.ObjectReference) CertificateRequestModifier {
	return func(c *v1alpha1.CertificateRequest) {
		c.Spec.IssuerRef = o
	}
}

func SetCertificateRequestCSR(csr []byte) CertificateRequestModifier {
	return func(cr *v1alpha1.CertificateRequest) {
		cr.Spec.CSRPEM = csr
	}
}

func SetCertificateRequestIsCA(isCA bool) CertificateRequestModifier {
	return func(cr *v1alpha1.CertificateRequest) {
		cr.Spec.IsCA = isCA
	}
}

func SetCertificateRequestDuration(duration *metav1.Duration) CertificateRequestModifier {
	return func(cr *v1alpha1.CertificateRequest) {
		cr.Spec.Duration = duration
	}
}

func SetCertificateRequestCA(ca []byte) CertificateRequestModifier {
	return func(cr *v1alpha1.CertificateRequest) {
		cr.Status.CA = ca
	}
}

func SetCertificateRequestCertificate(cert []byte) CertificateRequestModifier {
	return func(cr *v1alpha1.CertificateRequest) {
		cr.Status.Certificate = cert
	}
}

func SetCertificateRequestStatusCondition(c v1alpha1.CertificateRequestCondition) CertificateRequestModifier {
	return func(cr *v1alpha1.CertificateRequest) {
		if len(cr.Status.Conditions) == 0 {
			cr.Status.Conditions = []v1alpha1.CertificateRequestCondition{c}
			return
		}
		for i, existingC := range cr.Status.Conditions {
			if existingC.Type == c.Type {
				cr.Status.Conditions[i] = c
				return
			}
		}
		cr.Status.Conditions = append(cr.Status.Conditions, c)
	}
}

func SetCertificateRequestNamespace(namespace string) CertificateRequestModifier {
	return func(cr *v1alpha1.CertificateRequest) {
		cr.ObjectMeta.Namespace = namespace
	}
}

func SetCertificateRequestName(name string) CertificateRequestModifier {
	return func(cr *v1alpha1.CertificateRequest) {
		cr.ObjectMeta.Name = name
	}
}
