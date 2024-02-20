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
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type CertificateModifier func(*v1.Certificate)

func Certificate(name string, mods ...CertificateModifier) *v1.Certificate {
	c := &v1.Certificate{
		ObjectMeta: ObjectMeta(name),
		Spec: v1.CertificateSpec{
			PrivateKey: &v1.CertificatePrivateKey{},
		},
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func CertificateFrom(crt *v1.Certificate, mods ...CertificateModifier) *v1.Certificate {
	crt = crt.DeepCopy()
	for _, mod := range mods {
		mod(crt)
	}
	return crt
}

// SetIssuer sets the Certificate.spec.issuerRef field
func SetCertificateIssuer(o cmmeta.ObjectReference) CertificateModifier {
	return func(c *v1.Certificate) {
		c.Spec.IssuerRef = o
	}
}

func SetCertificateDNSNames(dnsNames ...string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.DNSNames = dnsNames
	}
}

func SetCertificateCommonName(commonName string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.CommonName = commonName
	}
}

func SetCertificateIPs(ips ...string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.IPAddresses = ips
	}
}

func SetCertificateEmails(emails ...string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.EmailAddresses = emails
	}
}

func SetCertificateURIs(uris ...string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.URIs = uris
	}
}

func SetCertificateIsCA(isCA bool) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.IsCA = isCA
	}
}

func SetCertificateKeyAlgorithm(keyAlgorithm v1.PrivateKeyAlgorithm) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.PrivateKey.Algorithm = keyAlgorithm
	}
}

func SetCertificateKeySize(keySize int) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.PrivateKey.Size = keySize
	}
}

func SetCertificateKeyEncoding(keyEncoding v1.PrivateKeyEncoding) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.PrivateKey.Encoding = keyEncoding
	}
}

func SetCertificateSecretName(secretName string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.SecretName = secretName
	}
}

// SetCertificateSecretTemplate sets annotations and labels to be attached to the secret metadata.
func SetCertificateSecretTemplate(annotations, labels map[string]string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.SecretTemplate = &v1.CertificateSecretTemplate{
			Annotations: annotations,
			Labels:      labels,
		}
	}
}

func SetCertificateDuration(duration *metav1.Duration) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.Duration = duration
	}
}

func SetCertificateRenewBefore(renewBefore *metav1.Duration) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.RenewBefore = renewBefore
	}
}

func SetCertificateNextPrivateKeySecretName(name string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Status.NextPrivateKeySecretName = &name
	}
}

func SetCertificateStatusCondition(c v1.CertificateCondition) CertificateModifier {
	return func(crt *v1.Certificate) {
		if len(crt.Status.Conditions) == 0 {
			crt.Status.Conditions = []v1.CertificateCondition{c}
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
	return func(crt *v1.Certificate) {
		crt.Status.LastFailureTime = &p
	}
}
func SetCertificateIssuanceAttempts(ia *int) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Status.FailedIssuanceAttempts = ia
	}
}

func SetCertificateNotAfter(p metav1.Time) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Status.NotAfter = &p
	}
}

func SetCertificateNotBefore(p metav1.Time) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Status.NotBefore = &p
	}
}

func SetCertificateRenewalTime(p metav1.Time) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Status.RenewalTime = &p
	}
}

func SetCertificateOrganization(orgs ...string) CertificateModifier {
	return func(ch *v1.Certificate) {
		if ch.Spec.Subject == nil {
			ch.Spec.Subject = &v1.X509Subject{}
		}
		ch.Spec.Subject.Organizations = orgs
	}
}

func SetCertificateNamespace(namespace string) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.ObjectMeta.Namespace = namespace
	}
}

func SetCertificateKeyUsages(usages ...v1.KeyUsage) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.Usages = usages
	}
}

func SetCertificateRevision(revision int) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Status.Revision = &revision
	}
}

func SetCertificateUID(uid types.UID) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.UID = uid
	}
}

func SetCertificateGeneration(gen int64) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Generation = gen
	}
}

func SetCertificateCreationTimestamp(creationTimestamp metav1.Time) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.ObjectMeta.CreationTimestamp = creationTimestamp
	}
}

func AddCertificateAnnotations(annotations map[string]string) CertificateModifier {
	return func(crt *v1.Certificate) {
		if crt.Annotations == nil {
			crt.Annotations = make(map[string]string)
		}

		for k, v := range annotations {
			crt.Annotations[k] = v
		}
	}
}

func AddCertificateLabels(labels map[string]string) CertificateModifier {
	return func(crt *v1.Certificate) {
		if crt.Labels == nil {
			crt.Labels = make(map[string]string)
		}
		for k, v := range labels {
			crt.Labels[k] = v
		}
	}
}

// CertificateRef creates an owner reference for a certificate without having to
// give the full certificate. Only use this function for testing purposes.
//
// Note that the only "important" field that must be filled in ownerReference
// [1] is the UID. Most notably, the IsControlledBy function [2] only cares
// about the UID. The apiVersion, kind and name are only used for information
// purposes.
//
//	[1]: https://github.com/kubernetes/apimachinery/blob/10b3882/pkg/apis/meta/v1/types.go#L273-L275
//	[2]: https://github.com/kubernetes/apimachinery/blob/10b3882/pkg/apis/meta/v1/controller_ref.go#L29
func CertificateRef(certName, certUID string) metav1.OwnerReference {
	return *metav1.NewControllerRef(
		Certificate(certName,
			SetCertificateUID(types.UID(certUID)),
		),
		v1.SchemeGroupVersion.WithKind("Certificate"),
	)
}

func SetCertificateRevisionHistoryLimit(limit int32) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.RevisionHistoryLimit = &limit
	}
}

func SetCertificateAdditionalOutputFormats(additionalOutputFormats ...v1.CertificateAdditionalOutputFormat) CertificateModifier {
	return func(crt *v1.Certificate) {
		crt.Spec.AdditionalOutputFormats = additionalOutputFormats
	}
}
