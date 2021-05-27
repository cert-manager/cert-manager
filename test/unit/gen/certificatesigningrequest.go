/*
Copyright 2021 The cert-manager Authors.

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
	"encoding/base64"
	"strconv"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	experimentalapi "github.com/jetstack/cert-manager/pkg/apis/experimental/v1alpha1"
)

type CertificateSigningRequestModifier func(*certificatesv1.CertificateSigningRequest)

func CertificateSigningRequest(name string, mods ...CertificateSigningRequestModifier) *certificatesv1.CertificateSigningRequest {
	c := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: make(map[string]string),
			Labels:      make(map[string]string),
		},
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func CertificateSigningRequestFrom(cr *certificatesv1.CertificateSigningRequest, mods ...CertificateSigningRequestModifier) *certificatesv1.CertificateSigningRequest {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

func SetCertificateSigningRequestIsCA(isCA bool) CertificateSigningRequestModifier {
	return AddCertificateSigningRequestAnnotations(map[string]string{
		experimentalapi.CertificateSigningRequestIsCAAnnotationKey: strconv.FormatBool(isCA),
	})
}

func SetCertificateSigningRequestRequest(request []byte) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		csr.Spec.Request = request
	}
}

func AddCertificateSigningRequestAnnotations(annotations map[string]string) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		// Make sure to do a merge here with new annotations overriding.
		annotationsNew := csr.GetAnnotations()
		if annotationsNew == nil {
			annotationsNew = make(map[string]string)
		}
		for k, v := range annotations {
			annotationsNew[k] = v
		}
		csr.SetAnnotations(annotationsNew)
	}
}

func SetCertificateSigningRequestSignerName(signerName string) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		csr.Spec.SignerName = signerName
	}
}

func SetCertificateSigningRequestDuration(duration string) CertificateSigningRequestModifier {
	return AddCertificateSigningRequestAnnotations(map[string]string{
		experimentalapi.CertificateSigningRequestDurationAnnotationKey: duration,
	})
}

func SetCertificateSigningRequestCertificate(cert []byte) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		csr.Status.Certificate = cert
	}
}

func SetCertificateSigningRequestCA(ca []byte) CertificateSigningRequestModifier {
	return AddCertificateSigningRequestAnnotations(map[string]string{
		experimentalapi.CertificateSigningRequestCAAnnotationKey: base64.StdEncoding.EncodeToString(ca),
	})
}

func SetCertificateSigningRequestStatusCondition(c certificatesv1.CertificateSigningRequestCondition) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		if len(csr.Status.Conditions) == 0 {
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{c}
			return
		}

		for i, existingC := range csr.Status.Conditions {
			if existingC.Type == c.Type {
				csr.Status.Conditions[i] = c
				return
			}
		}
		csr.Status.Conditions = append(csr.Status.Conditions, c)
	}
}

func SetCertificateSigningRequestUsername(username string) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		csr.Spec.Username = username
	}
}

func SetCertificateSigningRequestGroups(groups []string) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		csr.Spec.Groups = groups
	}
}

func SetCertificateSigningRequestUID(uid string) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		csr.Spec.UID = uid
	}
}

func SetCertificateSigningRequestExtra(extra map[string]certificatesv1.ExtraValue) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		csr.Spec.Extra = extra
	}
}

func SetCertificateSigningRequestUsages(usages []certificatesv1.KeyUsage) CertificateSigningRequestModifier {
	return func(csr *certificatesv1.CertificateSigningRequest) {
		csr.Spec.Usages = usages
	}
}
