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

package gen

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type CertificateRequestModifier func(*v1.CertificateRequest)

func CertificateRequest(name string, mods ...CertificateRequestModifier) *v1.CertificateRequest {
	c := &v1.CertificateRequest{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func CertificateRequestFrom(cr *v1.CertificateRequest, mods ...CertificateRequestModifier) *v1.CertificateRequest {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

// SetCertificateRequestIssuer sets the CertificateRequest.spec.issuerRef field
func SetCertificateRequestIssuer(o cmmeta.ObjectReference) CertificateRequestModifier {
	return func(c *v1.CertificateRequest) {
		c.Spec.IssuerRef = o
	}
}

func SetCertificateRequestCSR(csr []byte) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Spec.Request = csr
	}
}

func SetCertificateRequestIsCA(isCA bool) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Spec.IsCA = isCA
	}
}

func SetCertificateRequestDuration(duration *metav1.Duration) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Spec.Duration = duration
	}
}

func SetCertificateRequestCA(ca []byte) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Status.CA = ca
	}
}

func SetCertificateRequestCertificate(cert []byte) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Status.Certificate = cert
	}
}

func SetCertificateRequestStatusCondition(c v1.CertificateRequestCondition) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		if len(cr.Status.Conditions) == 0 {
			cr.Status.Conditions = []v1.CertificateRequestCondition{c}
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

func AddCertificateRequestStatusCondition(c v1.CertificateRequestCondition) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Status.Conditions = append(cr.Status.Conditions, c)
	}
}

func SetCertificateRequestNamespace(namespace string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.ObjectMeta.Namespace = namespace
	}
}

func SetCertificateRequestName(name string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.ObjectMeta.Name = name
	}
}

func SetCertificateRequestGenerateName(generateName string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.ObjectMeta.GenerateName = generateName
	}
}

func SetCertificateRequestKeyUsages(usages ...v1.KeyUsage) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Spec.Usages = usages
	}
}

func AddCertificateRequestAnnotations(annotations map[string]string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
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

func AddCertificateRequestOwnerReferences(owners ...metav1.OwnerReference) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.OwnerReferences = append(cr.OwnerReferences, owners...)
	}
}

func SetCertificateRequestAnnotations(annotations map[string]string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		if cr.Annotations == nil {
			cr.Annotations = make(map[string]string)
		}
		for k, v := range annotations {
			cr.Annotations[k] = v
		}
	}
}

func DeleteCertificateRequestAnnotation(key string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		if cr.Annotations == nil {
			return
		}
		delete(cr.Annotations, key)
	}
}

func SetCertificateRequestFailureTime(p metav1.Time) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Status.FailureTime = &p
	}
}

func SetCertificateRequestTypeMeta(tm metav1.TypeMeta) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.TypeMeta = tm
	}
}

func SetCertificateRequestUsername(username string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Spec.Username = username
	}
}

func SetCertificateRequestGroups(groups []string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		cr.Spec.Groups = groups
	}
}

func SetCertificateRequestRevision(rev string) CertificateRequestModifier {
	return func(cr *v1.CertificateRequest) {
		if cr.Annotations == nil {
			cr.Annotations = make(map[string]string)
		}

		cr.Annotations[v1.CertificateRequestRevisionAnnotationKey] = rev
	}
}
