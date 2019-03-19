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

package util

// TODO: we should break this file apart into separate more sane/reusable parts

import (
	"crypto/x509"
	"fmt"
	"time"

	intscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	"k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/test/e2e/framework/log"
)

func CertificateOnlyValidForDomains(cert *x509.Certificate, commonName string, dnsNames ...string) bool {
	if commonName != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, dnsNames) {
		return false
	}
	return true
}

func WaitForIssuerStatusFunc(client clientset.IssuerInterface, name string, fn func(*v1alpha1.Issuer) (bool, error)) error {
	return wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			issuer, err := client.Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}
			return fn(issuer)
		})
}

// WaitForIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func WaitForIssuerCondition(client clientset.IssuerInterface, name string, condition v1alpha1.IssuerCondition) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			log.Logf("Waiting for issuer %v condition %#v", name, condition)
			issuer, err := client.Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}

			return apiutil.IssuerHasCondition(issuer, condition), nil
		},
	)
	return wrapErrorWithIssuerStatusCondition(client, pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithIssuerStatusCondition(client clientset.IssuerInterface, pollErr error, name string, conditionType v1alpha1.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	issuer, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		return pollErr
	}

	for _, cond := range issuer.GetStatus().Conditions {
		if cond.Type == conditionType {
			return fmt.Errorf("%s: Last Status: '%s' Reason: '%s', Message: '%s'", pollErr.Error(), cond.Status, cond.Reason, cond.Message)
		}

	}

	return pollErr
}

// WaitForClusterIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func WaitForClusterIssuerCondition(client clientset.ClusterIssuerInterface, name string, condition v1alpha1.IssuerCondition) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			log.Logf("Waiting for clusterissuer %v condition %#v", name, condition)
			issuer, err := client.Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting ClusterIssuer %v: %v", name, err)
			}

			return apiutil.IssuerHasCondition(issuer, condition), nil
		},
	)
	return wrapErrorWithClusterIssuerStatusCondition(client, pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithClusterIssuerStatusCondition(client clientset.ClusterIssuerInterface, pollErr error, name string, conditionType v1alpha1.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	issuer, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		return pollErr
	}

	for _, cond := range issuer.GetStatus().Conditions {
		if cond.Type == conditionType {
			return fmt.Errorf("%s: Last Status: '%s' Reason: '%s', Message: '%s'", pollErr.Error(), cond.Status, cond.Reason, cond.Message)
		}

	}

	return pollErr
}

// WaitForCertificateCondition waits for the status of the named Certificate to contain
// a condition whose type and status matches the supplied one.
func WaitForCertificateCondition(client clientset.CertificateInterface, name string, condition v1alpha1.CertificateCondition, timeout time.Duration) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			log.Logf("Waiting for Certificate %v condition %#v", name, condition)
			certificate, err := client.Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}

			return apiutil.CertificateHasCondition(certificate, condition), nil
		},
	)
	return wrapErrorWithCertificateStatusCondition(client, pollErr, name, condition.Type)
}

// WaitForCertificateEvent waits for an event on the named Certificate to contain
// an event reason matches the supplied one.
func WaitForCertificateEvent(client kubernetes.Interface, cert *v1alpha1.Certificate, reason string, timeout time.Duration) error {
	return wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			log.Logf("Waiting for Certificate event %v reason %#v", cert.Name, reason)
			evts, err := client.Core().Events(cert.Namespace).Search(intscheme.Scheme, cert)
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", cert.Name, err)
			}

			return hasEvent(evts, reason), nil
		},
	)
}

func hasEvent(events *v1.EventList, reason string) bool {
	for _, evt := range events.Items {
		if evt.Reason == reason {
			return true
		}
	}
	return false
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithCertificateStatusCondition(client clientset.CertificateInterface, pollErr error, name string, conditionType v1alpha1.CertificateConditionType) error {
	if pollErr == nil {
		return nil
	}

	certificate, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		return pollErr
	}

	for _, cond := range certificate.Status.Conditions {
		if cond.Type == conditionType {
			return fmt.Errorf("%s: Last Status: '%s' Reason: '%s', Message: '%s'", pollErr.Error(), cond.Status, cond.Reason, cond.Message)
		}
	}

	return pollErr
}

// WaitForCertificateToExist waits for the named certificate to exist
func WaitForCertificateToExist(client clientset.CertificateInterface, name string, timeout time.Duration) error {
	return wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			log.Logf("Waiting for Certificate %v to exist", name)
			_, err := client.Get(name, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}

			return true, nil
		},
	)
}

// WaitForCRDToNotExist waits for the CRD with the given name to no
// longer exist.
func WaitForCRDToNotExist(client apiextcs.CustomResourceDefinitionInterface, name string) error {
	return wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			log.Logf("Waiting for CRD %v to not exist", name)
			_, err := client.Get(name, metav1.GetOptions{})
			if nil == err {
				return false, nil
			}

			if errors.IsNotFound(err) {
				return true, nil
			}

			return false, nil
		},
	)
}

func NewCertManagerCAClusterIssuer(name, secretName string) *v1alpha1.ClusterIssuer {
	return &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				CA: &v1alpha1.CAIssuer{
					SecretName: secretName,
				},
			},
		},
	}
}

func NewCertManagerBasicCertificate(name, secretName, issuerName string, issuerKind string, duration, renewBefore *metav1.Duration) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.CertificateSpec{
			CommonName:   "test.domain.com",
			Organization: []string{"test-org"},
			SecretName:   secretName,
			Duration:     duration,
			RenewBefore:  renewBefore,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
}

func NewCertManagerACMECertificate(name, secretName, issuerName string, issuerKind string, duration, renewBefore *metav1.Duration, ingressClass string, cn string, dnsNames ...string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.CertificateSpec{
			CommonName:  cn,
			DNSNames:    dnsNames,
			SecretName:  secretName,
			Duration:    duration,
			RenewBefore: renewBefore,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
			ACME: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains: append(dnsNames, cn),
						SolverConfig: v1alpha1.SolverConfig{
							HTTP01: &v1alpha1.HTTP01SolverConfig{
								IngressClass: &ingressClass,
							},
						},
					},
				},
			},
		},
	}
}

func NewCertManagerVaultCertificate(name, secretName, issuerName string, issuerKind string, duration, renewBefore *metav1.Duration) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.CertificateSpec{
			CommonName:  "test.domain.com",
			SecretName:  secretName,
			Duration:    duration,
			RenewBefore: renewBefore,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
}

func NewIngress(name, secretName string, annotations map[string]string, dnsNames ...string) *extv1beta1.Ingress {
	return &extv1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: extv1beta1.IngressSpec{
			TLS: []extv1beta1.IngressTLS{
				{
					Hosts:      dnsNames,
					SecretName: secretName,
				},
			},
			Rules: []extv1beta1.IngressRule{
				{
					Host: dnsNames[0],
					IngressRuleValue: extv1beta1.IngressRuleValue{
						HTTP: &extv1beta1.HTTPIngressRuleValue{
							Paths: []extv1beta1.HTTPIngressPath{
								{
									Path: "/",
									Backend: extv1beta1.IngressBackend{
										ServiceName: "dummy-service",
										ServicePort: intstr.FromInt(80),
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func NewCertManagerACMEIssuer(name, acmeURL, acmeEmail, acmePrivateKey string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: &v1alpha1.ACMEIssuer{
					Email:         acmeEmail,
					Server:        acmeURL,
					SkipTLSVerify: true,
					PrivateKey: v1alpha1.SecretKeySelector{
						LocalObjectReference: v1alpha1.LocalObjectReference{
							Name: acmePrivateKey,
						},
					},
					HTTP01: &v1alpha1.ACMEIssuerHTTP01Config{},
				},
			},
		},
	}
}

func NewCertManagerCAIssuer(name, secretName string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				CA: &v1alpha1.CAIssuer{
					SecretName: secretName,
				},
			},
		},
	}
}

func NewCertManagerSelfSignedIssuer(name string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				SelfSigned: &v1alpha1.SelfSignedIssuer{},
			},
		},
	}
}

func NewCertManagerVaultIssuerToken(name, vaultURL, vaultPath, vaultSecretToken, authPath string, caBundle []byte) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				Vault: &v1alpha1.VaultIssuer{
					Server:   vaultURL,
					Path:     vaultPath,
					CABundle: caBundle,
					Auth: v1alpha1.VaultAuth{
						TokenSecretRef: v1alpha1.SecretKeySelector{
							Key: "secretkey",
							LocalObjectReference: v1alpha1.LocalObjectReference{
								Name: vaultSecretToken,
							},
						},
					},
				},
			},
		},
	}
}

func NewCertManagerVaultIssuerAppRole(name, vaultURL, vaultPath, roleId, vaultSecretAppRole string, authPath string, caBundle []byte) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				Vault: &v1alpha1.VaultIssuer{
					Server:   vaultURL,
					Path:     vaultPath,
					CABundle: caBundle,
					Auth: v1alpha1.VaultAuth{
						AppRole: v1alpha1.VaultAppRole{
							Path:   authPath,
							RoleId: roleId,
							SecretRef: v1alpha1.SecretKeySelector{
								Key: "secretkey",
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: vaultSecretAppRole,
								},
							},
						},
					},
				},
			},
		},
	}
}
