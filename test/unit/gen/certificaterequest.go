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

func CertificateRequestFrom(crt *v1alpha1.CertificateRequest, mods ...CertificateRequestModifier) *v1alpha1.CertificateRequest {
	crt = crt.DeepCopy()
	for _, mod := range mods {
		mod(crt)
	}
	return crt
}

// SetIssuer sets the CertificateRequest.spec.issuerRef field
func SetCertificateRequestIssuer(o v1alpha1.ObjectReference) CertificateRequestModifier {
	return func(c *v1alpha1.CertificateRequest) {
		c.Spec.IssuerRef = o
	}
}

func SetCertificateRequestIsCA(isCA bool) CertificateRequestModifier {
	return func(crt *v1alpha1.CertificateRequest) {
		crt.Spec.IsCA = isCA
	}
}

func SetCertificateRequestCSRPEM(csrPEM []byte) CertificateRequestModifier {
	return func(crt *v1alpha1.CertificateRequest) {
		crt.Spec.CSRPEM = csrPEM
	}
}

func SetCertificateRequestStatusCondition(c v1alpha1.CertificateRequestCondition) CertificateRequestModifier {
	return func(crt *v1alpha1.CertificateRequest) {
		if len(crt.Status.Conditions) == 0 {
			crt.Status.Conditions = []v1alpha1.CertificateRequestCondition{c}
			return
		}
		for i, existingC := range crt.Status.Conditions {
			if existingC.Type == c.Type {
				crt.Status.Conditions[i] = c
				return
			}
		}
		crt.Status.Conditions = append(crt.Status.Conditions, c)
	}
}
