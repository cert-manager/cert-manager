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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

type CertificateModifier func(*v1alpha2.Certificate)

func Certificate(name string, mods ...CertificateModifier) *v1alpha2.Certificate {
	c := &v1alpha2.Certificate{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func CertificateFrom(crt *v1alpha2.Certificate, mods ...CertificateModifier) *v1alpha2.Certificate {
	crt = crt.DeepCopy()
	for _, mod := range mods {
		mod(crt)
	}
	return crt
}

// SetIssuer sets the Certificate.spec.issuerRef field
func SetCertificateIssuer(o cmmeta.ObjectReference) CertificateModifier {
	return func(c *v1alpha2.Certificate) {
		c.Spec.IssuerRef = o
	}
}

func SetCertificateDNSNames(dnsNames ...string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.DNSNames = dnsNames
	}
}

func SetCertificateCommonName(commonName string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.CommonName = commonName
	}
}

func SetCertificateIPs(ips ...string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.IPAddresses = ips
	}
}

func SetCertificateURIs(uris ...string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.URISANs = uris
	}
}

func SetCertificateIsCA(isCA bool) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.IsCA = isCA
	}
}

func SetCertificateKeyAlgorithm(keyAlgorithm v1alpha2.KeyAlgorithm) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.KeyAlgorithm = keyAlgorithm
	}
}

func SetCertificateKeySize(keySize int) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.KeySize = keySize
	}
}

func SetCertificateKeyEncoding(keyEncoding v1alpha2.KeyEncoding) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.KeyEncoding = keyEncoding
	}
}

func SetCertificateSecretName(secretName string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.SecretName = secretName
	}
}

func SetCertificateDuration(duration time.Duration) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.Duration = &metav1.Duration{Duration: duration}
	}
}

func SetCertificateRenewBefore(renewBefore time.Duration) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.RenewBefore = &metav1.Duration{Duration: renewBefore}
	}
}

func SetCertificateNextPrivateKeySecretName(name string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Status.NextPrivateKeySecretName = &name
	}
}

func SetCertificateStatusCondition(c v1alpha2.CertificateCondition) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		if len(crt.Status.Conditions) == 0 {
			crt.Status.Conditions = []v1alpha2.CertificateCondition{c}
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

func SetCertificateLastFailureTime(p metav1.Time) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Status.LastFailureTime = &p
	}
}

func SetCertificateNotAfter(p metav1.Time) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Status.NotAfter = &p
	}
}

func SetCertificateNotBefore(p metav1.Time) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Status.NotBefore = &p
	}
}

func SetCertificateRenewalTIme(p metav1.Time) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Status.RenewalTime = &p
	}
}

func SetCertificateOrganization(orgs ...string) CertificateModifier {
	return func(ch *v1alpha2.Certificate) {
		ch.Spec.Organization = orgs
	}
}

func SetCertificateNamespace(namespace string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.ObjectMeta.Namespace = namespace
	}
}

func SetCertificateKeyUsages(usages ...v1alpha2.KeyUsage) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Spec.Usages = usages
	}
}

func SetCertificateRevision(revision int) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.Status.Revision = &revision
	}
}

func SetCertificateUID(uid types.UID) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		crt.UID = uid
	}
}

func AddCertificateAnnotations(annotations map[string]string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		if crt.Annotations == nil {
			crt.Annotations = make(map[string]string)
		}

		for k, v := range annotations {
			crt.Annotations[k] = v
		}
	}
}

func AddCertificateLabels(labels map[string]string) CertificateModifier {
	return func(crt *v1alpha2.Certificate) {
		if crt.Labels == nil {
			crt.Labels = make(map[string]string)
		}
		for k, v := range labels {
			crt.Labels[k] = v
		}
	}
}
