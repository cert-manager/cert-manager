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

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

type CertificateRequestModifier func(*v1alpha2.CertificateRequest)

func CertificateRequest(name string, mods ...CertificateRequestModifier) *v1alpha2.CertificateRequest {
	c := &v1alpha2.CertificateRequest{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func CertificateRequestFrom(cr *v1alpha2.CertificateRequest, mods ...CertificateRequestModifier) *v1alpha2.CertificateRequest {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

// SetIssuer sets the CertificateRequest.spec.issuerRef field
func SetCertificateRequestIssuer(o cmmeta.ObjectReference) CertificateRequestModifier {
	return func(c *v1alpha2.CertificateRequest) {
		c.Spec.IssuerRef = o
	}
}

func SetCertificateRequestCSR(csr []byte) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.Spec.CSRPEM = csr
	}
}

func SetCertificateRequestIsCA(isCA bool) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.Spec.IsCA = isCA
	}
}

func SetCertificateRequestDuration(duration *metav1.Duration) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.Spec.Duration = duration
	}
}

func SetCertificateRequestCA(ca []byte) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.Status.CA = ca
	}
}

func SetCertificateRequestCertificate(cert []byte) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.Status.Certificate = cert
	}
}

func SetCertificateRequestStatusCondition(c v1alpha2.CertificateRequestCondition) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		if len(cr.Status.Conditions) == 0 {
			cr.Status.Conditions = []v1alpha2.CertificateRequestCondition{c}
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
	return func(cr *v1alpha2.CertificateRequest) {
		cr.ObjectMeta.Namespace = namespace
	}
}

func SetCertificateRequestName(name string) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.ObjectMeta.Name = name
	}
}

func SetCertificateRequestKeyUsages(usages ...v1alpha2.KeyUsage) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.Spec.Usages = usages
	}
}

func AddCertificateRequestAnnotations(annotations map[string]string) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		// Make sure to do a merge here with new annotations overriding.
		annotationsNew := cr.GetAnnotations()
		if annotationsNew == nil {
			annotationsNew = make(map[string]string)
		}
		for k, v := range annotations {
			annotationsNew[k] = v
		}
		cr.SetAnnotations(annotationsNew)
	}
}

func SetCertificateRequestAnnotations(annotations map[string]string) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.SetAnnotations(annotations)
	}
}

func SetCertificateRequestFailureTime(p metav1.Time) CertificateRequestModifier {
	return func(cr *v1alpha2.CertificateRequest) {
		cr.Status.FailureTime = &p
	}
}
