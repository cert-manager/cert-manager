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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	intscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	"k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corecs "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
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

			return issuer.HasCondition(condition), nil
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

			return issuer.HasCondition(condition), nil
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

			return certificate.HasCondition(condition), nil
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

// WaitCertificateIssuedValid waits for the given Certificate to be
// 'Ready' and ensures the stored certificate is valid for the specified
// domains.
func WaitCertificateIssuedValidTLS(certClient clientset.CertificateInterface, secretClient corecs.SecretInterface, name string, timeout time.Duration, validateTLS bool) error {
	return wait.PollImmediate(time.Second, timeout,
		func() (bool, error) {
			log.Logf("Waiting for Certificate %v to be ready", name)
			certificate, err := certClient.Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			isReady := certificate.HasCondition(v1alpha1.CertificateCondition{
				Type:   v1alpha1.CertificateConditionReady,
				Status: v1alpha1.ConditionTrue,
			})
			if !isReady {
				return false, nil
			}
			log.Logf("Getting the TLS certificate Secret resource")
			secret, err := secretClient.Get(certificate.Spec.SecretName, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					return false, nil
				}

				return false, err
			}
			if !(len(secret.Data) == 2 || len(secret.Data) == 3) {
				log.Logf("Expected 2 keys in certificate secret, but there was %d", len(secret.Data))
				return false, nil
			}

			keyBytes, ok := secret.Data[v1.TLSPrivateKeyKey]
			if !ok {
				log.Logf("No private key data found for Certificate %q (secret %q)", name, certificate.Spec.SecretName)
				return false, nil
			}
			key, err := pki.DecodePrivateKeyBytes(keyBytes)
			if err != nil {
				return false, err
			}

			// validate private key is of the correct type (rsa or ecdsa)
			switch certificate.Spec.KeyAlgorithm {
			case v1alpha1.KeyAlgorithm(""),
				v1alpha1.RSAKeyAlgorithm:
				_, ok := key.(*rsa.PrivateKey)
				if !ok {
					log.Logf("Expected private key of type RSA, but it was: %T", key)
					return false, nil
				}
			case v1alpha1.ECDSAKeyAlgorithm:
				_, ok := key.(*ecdsa.PrivateKey)
				if !ok {
					log.Logf("Expected private key of type ECDSA, but it was: %T", key)
					return false, nil
				}
			default:
				return false, fmt.Errorf("unrecognised requested private key algorithm %q", certificate.Spec.KeyAlgorithm)
			}

			// TODO: validate private key KeySize

			// check the provided certificate is valid
			expectedCN := pki.CommonNameForCertificate(certificate)
			expectedOrganization := pki.OrganizationForCertificate(certificate)
			expectedDNSNames := pki.DNSNamesForCertificate(certificate)

			certBytes, ok := secret.Data[v1.TLSCertKey]
			if !ok {
				log.Logf("No certificate data found for Certificate %q (secret %q)", name, certificate.Spec.SecretName)
				return false, nil
			}

			cert, err := pki.DecodeX509CertificateBytes(certBytes)
			if err != nil {
				return false, err
			}
			if expectedCN != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, expectedDNSNames) || !(len(cert.Subject.Organization) == 0 || util.EqualUnsorted(cert.Subject.Organization, expectedOrganization)) {
				log.Logf("Expected certificate valid for CN %q, O %v, dnsNames %v but got a certificate valid for CN %q, O %v, dnsNames %v", expectedCN, expectedOrganization, expectedDNSNames, cert.Subject.CommonName, cert.Subject.Organization, cert.DNSNames)
				return false, nil
			}

			if certificate.Status.NotAfter == nil {
				log.Logf("No certificate expiration found for Certificate %q", name)
				return false, nil
			}
			if !cert.NotAfter.Equal(certificate.Status.NotAfter.Time) {
				log.Logf("Expected certificate expiry date to be %v, but got %v", certificate.Status.NotAfter, cert.NotAfter)
				return false, nil
			}

			label, ok := secret.Labels[v1alpha1.CertificateNameKey]
			if !ok {
				return false, fmt.Errorf("Expected secret to have certificate-name label, but had none")
			}

			if label != certificate.Name {
				return false, fmt.Errorf("Expected secret to have certificate-name label with a value of %q, but got %q", certificate.Name, label)
			}

			// Run TLS Verification
			if validateTLS {
				rootCertPool := x509.NewCertPool()
				rootCertPool.AppendCertsFromPEM([]byte(rootCert))
				intermediateCertPool := x509.NewCertPool()
				intermediateCertPool.AppendCertsFromPEM(certBytes)
				opts := x509.VerifyOptions{
					DNSName:       expectedDNSNames[0],
					Intermediates: intermediateCertPool,
					Roots:         rootCertPool,
				}

				if _, err := cert.Verify(opts); err != nil {
					return false, err
				}
			}

			return true, nil
		},
	)
}

func WaitCertificateIssuedValid(certClient clientset.CertificateInterface, secretClient corecs.SecretInterface, name string, timeout time.Duration) error {
	return WaitCertificateIssuedValidTLS(certClient, secretClient, name, timeout, false)
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

const rootCert = `-----BEGIN CERTIFICATE-----
MIID4DCCAsigAwIBAgIJAJzTROInmDkQMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNV
BAYTAlVLMQswCQYDVQQIEwJOQTEVMBMGA1UEChMMY2VydC1tYW5hZ2VyMSAwHgYD
VQQDExdjZXJ0LW1hbmFnZXIgdGVzdGluZyBDQTAeFw0xNzA5MTAxODMzNDNaFw0y
NzA5MDgxODMzNDNaMFMxCzAJBgNVBAYTAlVLMQswCQYDVQQIEwJOQTEVMBMGA1UE
ChMMY2VydC1tYW5hZ2VyMSAwHgYDVQQDExdjZXJ0LW1hbmFnZXIgdGVzdGluZyBD
QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM+Q2AO4hARav0qwjk7I
4mEh5R201HS8s7HpaLOXBNvvh7qJ9yJz6jLqYg6EvP0K/bK56Cp2oe2igd7GOxpV
3YPOc3CG0CCqHMprEcvxj2xBKX00Rtcn4oVLhDPhAb0BV/R7NFLeWxzh+ggvPI1X
m1qLaWYqYZEJ5bBsYXD3tPdS4GGINRz8Zvih46f0Z2wVkCGoTpsbX8HO74sa2Day
UjzAsWGlO5bZGiMSHjDEnf9yek2TcjEyVoohoOLaQg/ng21T5RWzeZKTl1cznwuG
Vr9tZfHFqxQ5qeaId+1ICtxNvkEjbTnZl6Wy9Cthn0dxwOeS5TqMJ7SFNXy1gp4j
f/MCAwEAAaOBtjCBszAdBgNVHQ4EFgQUBtrjvWfbkLA0iX6sKVRhKUo864kwgYMG
A1UdIwR8MHqAFAba471n25CwNIl+rClUYSlKPOuJoVekVTBTMQswCQYDVQQGEwJV
SzELMAkGA1UECBMCTkExFTATBgNVBAoTDGNlcnQtbWFuYWdlcjEgMB4GA1UEAxMX
Y2VydC1tYW5hZ2VyIHRlc3RpbmcgQ0GCCQCc00TiJ5g5EDAMBgNVHRMEBTADAQH/
MA0GCSqGSIb3DQEBCwUAA4IBAQCR+jXhup5tCKwhAf8xgvp589BczQOjmotuZGEL
Dcint2y263ChEdsoLhyJfvFCAZfTSm+UT95Hl+ZKVuoVEcAS7udaFUFpC/gIYVOi
H4/uvJps4SpVCB7+T/orcTjZ2ewT23mQAQg+B+iwX9VCof+fadkYOg1XD9/eaj6E
9McXID3iuCXg02RmEOwVMrTggHPwHrOGAilSaZc58cJZHmMYlT5rGrJcWS/AyXnH
VOodKC004yjh7w9aSbCCbAL0tDEnhm4Jrb8cxt7pDWbdEVUeuk9LZRQtluYBnmJU
kQ7ALfUfUh/RUpCV4uI6sEI3NDX2YqQbOtsBD/hNaL1F85FA
-----END CERTIFICATE-----`

const rootKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz5DYA7iEBFq/SrCOTsjiYSHlHbTUdLyzselos5cE2++Huon3
InPqMupiDoS8/Qr9srnoKnah7aKB3sY7GlXdg85zcIbQIKocymsRy/GPbEEpfTRG
1yfihUuEM+EBvQFX9Hs0Ut5bHOH6CC88jVebWotpZiphkQnlsGxhcPe091LgYYg1
HPxm+KHjp/RnbBWQIahOmxtfwc7vixrYNrJSPMCxYaU7ltkaIxIeMMSd/3J6TZNy
MTJWiiGg4tpCD+eDbVPlFbN5kpOXVzOfC4ZWv21l8cWrFDmp5oh37UgK3E2+QSNt
OdmXpbL0K2GfR3HA55LlOowntIU1fLWCniN/8wIDAQABAoIBAQCYvGvIKSG0FpbG
vi6pmLbEZO20s1jW4fiUxT2PUWR49sR4pocdahB/EOvA5TowNcNDnftSK+Ox+q/4
HwRkt6R+Fg/qULmcH7F53dnFqeYw8a42/J3YOvg7v7rzdfISg4eWVobFJ+wBz+Nt
3FyBYWLm+MlBLZSH5rGG5em59/zJNHWIhH+oQPfCxAkYEvd8tXOTUzjhqvEfjaJy
FZghnT9xto4MwDdNCPbtzdNjTMhiv0AHkcZGGtRJfkehXX2qhXOQ2UzzO9XrMZnv
5KgYf+bXKJsyS3SPl6TTl7vg2gKBciRvsdFhMy5I5GyIADrEDJnNNmXQRtiaFLfd
k/aqfPT5AoGBAPquMouZUbVS/Qh+qbls7G4zAuznfCiqdctcKmUGPRP4sTTjWdUp
fjI+UTt1e8hncmr4RY7Oa9kUV/kDwzS5spUZZ+u0PczS3XKxOwNOleoH00dfc9vt
cxctHdPdDTndRi8Z4k3m931jIX7jB/Pyx8qeNYB3pj0k3ThktwMbAVLnAoGBANP4
beI5zpbvtAdExJcuxx2mRDGF0lIdKC0bvQaeqM3Lwqnmc0Fz1dbP7KXDa+SdJWPd
res+NHPZoEPeEJuDTSngXOLNECZe4Ja9frn1TeY858vMJBwIkyc8zu+sgXxjQUM+
TWUlTUhtXyybkRnxAEny4OT2TTgmXITJaKOmV1UVAoGAHaXSlo4YitB42rNYUXTf
dZ0U4H30Qj7+1YFeBjq5qI4GL1IgQsS4hyq1osmfTTFm593bJCunt7HfQbU/NhIs
W9P4ZXkYwgvCYxkw+JAnzNkGFO/mHQG1Ve1hFLiVIt3XuiRejoYdiTfbM02YmDKD
jKQvgbUk9SBSBaRrvLNJ8csCgYAYnrZEnGo+ZcEHRxl+ZdSCwRkSl3SCTRiphJtD
9ZGttYj6quWgKJAhzyyxZC1X9FivbMQSmrsE6bYPq+9J4MpJnuGrBh5mFocHeyMI
/lD5+QEDTsay6twMpqdydxrjE7Q01zuuD9MWIn33dGo6FR/vduJgNatqZipA0hPx
ThS+sQKBgQDh0+cVo1mfYiCkp3IQPB8QYiJ/g2/UBk6pH8ZZDZ+A5td6NveiWO1y
wTEUWkX2qyz9SLxWDGOhdKqxNrLCUSYSOV/5/JQEtBm6K50ArFtrY40JP/T/5KvM
tSK2ayFX1wQ3PuEmewAogy/20tWo80cr556AXA62Utl2PzLK30Db8w==
-----END RSA PRIVATE KEY-----`

func NewSigningKeypairSecret(name string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			v1.TLSCertKey:       rootCert,
			v1.TLSPrivateKeyKey: rootKey,
		},
	}
}

const issuer1Cert = `-----BEGIN CERTIFICATE-----
MIIDnjCCAoagAwIBAgIUCAJmM4rqnkj65/0sFRSIjXNlmGYwDQYJKoZIhvcNAQEL
BQAwUzELMAkGA1UEBhMCVUsxCzAJBgNVBAgTAk5BMRUwEwYDVQQKEwxjZXJ0LW1h
bmFnZXIxIDAeBgNVBAMTF2NlcnQtbWFuYWdlciB0ZXN0aW5nIENBMB4XDTE4MTEx
NTAwMDQwMFoXDTIzMTExNDAwMDQwMFowVzELMAkGA1UEBhMCVUsxCzAJBgNVBAgT
Ak5BMRUwEwYDVQQKEwxjZXJ0LW1hbmFnZXIxJDAiBgNVBAMTG2NlcnQtbWFuYWdl
ciB0ZXN0aW5nIElzc3VlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AKubAgcLJfXspsDNNR/TO+UUy0s9DE28w4OXs7pAppe7rtK1a531M9lGg+jZPryT
PER4HeobhIk7h1iTmcVHp1mDB3IFDfKL8jKNEnsHGTcn5xY1RkFihFPphBiyGwvY
S4nGi1NubxTA+kW0Pbcf3po2NWNdntAHaMcvMEkq+NdoSEK1HACHQ8QqtqfKUxMD
XMFDmJD21/4PM6iqhDw2HPe87FY7KKdYAsMV8KnT5DIGJ6UbuarTuMzXZq0a8/aW
sto/hrBJir+CQwmNIYg41G8m1CgUz0a3FYxtvLNZweeW9+SiVl0FCiajLws0HIW5
4RTJ44Omr2/byIB+lmV63AMCAwEAAaNmMGQwDgYDVR0PAQH/BAQDAgGmMBIGA1Ud
EwEB/wQIMAYBAf8CAQMwHQYDVR0OBBYEFESJnTHvnJn8qIOb/JD+nw4o0yxnMB8G
A1UdIwQYMBaAFAba471n25CwNIl+rClUYSlKPOuJMA0GCSqGSIb3DQEBCwUAA4IB
AQBre0a1hD4T0W9E/yGhk6O8k11i63vhgIcMeN1/RMtgJRwIWIf3iKXAwAeIjkXZ
eGGSNWh8pC1wFvE9LIomhZLPSn+98FJ9dLfcaQXDOEyZM71OTsWQKS4NVNloHOxV
zujEujIIZ4caVbOlQWxf7lPydnXP+S7GsMU8vlOsU2RC9jN+yeuho+ZVguSC76ni
CG+k/Lzf46CMAZtRLdv9FPFttodBnodapOEgkhGwhyz/J6eLR1t9DWlxpQ1vk45H
dT3HDz1CNlF/5HzYpVBus553Z7SFh2x1umKfmTUWqmbFsslr2y4w2nkhyG2+jH+k
lh+Eve9i4q7YaO0EMlOOJMar
-----END CERTIFICATE-----
`

const issuer1Key = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAq5sCBwsl9eymwM01H9M75RTLSz0MTbzDg5ezukCml7uu0rVr
nfUz2UaD6Nk+vJM8RHgd6huEiTuHWJOZxUenWYMHcgUN8ovyMo0SewcZNyfnFjVG
QWKEU+mEGLIbC9hLicaLU25vFMD6RbQ9tx/emjY1Y12e0Adoxy8wSSr412hIQrUc
AIdDxCq2p8pTEwNcwUOYkPbX/g8zqKqEPDYc97zsVjsop1gCwxXwqdPkMgYnpRu5
qtO4zNdmrRrz9pay2j+GsEmKv4JDCY0hiDjUbybUKBTPRrcVjG28s1nB55b35KJW
XQUKJqMvCzQchbnhFMnjg6avb9vIgH6WZXrcAwIDAQABAoIBAHm3VFTSn3YzCIOw
CYItPUpa2WbgQh3RSYvIyf3NZVwyDun9K/u5s7DkxyMdE9aFSDX4TJ+ELRl5U6KL
7oFzNUvUGC/TTfU/NeaNERKaElSAxPOHjfFKgzlRZBRwH6bjH5D1dlUS+07pIZrX
IP8GZ8lRscRs3vwGhVbiLYl4JVACydgyV/Th1yJYFEOXlmHV4Kk0ce3swsXL0NUb
BFQ53RULSxLVaYy4XXF3azSUdMkalDf8DxxeFtPUSW49zp6/iOArZTNCoiGavOHo
YvtnUXjt2QK64SdjFYMyCD8EcLlMTOUtAS10lw9NwUS3JMp3u79bO2uvRwJpT+IP
Hb0Sg8ECgYEAyi41EwEE6cwNVOAZxkOgv+ejhBjKuUrhzp0vwg3Uziuy6TZPJEoA
5e/8pFuvxbfU0lGUe6CkHdpSQPO7ifsTuxYxO/ZX8DqSaCwnRp+kJUyi7Jz3Ypfk
LsVg3TMW9Hmvntz8kPTN8DJMo6W7TC0m05L5pyfvM2BpBXqYIPNLInkCgYEA2Uk8
mnA43ME+oaqLxcqgIE1+AXeg+voH17kiuO7hVWlprxJv/b6AAjm0nxcuLcdofKJT
JgaWrwyhI676q5T/lqQn/gdJ7rwz/83WnforW7WVza2XT+aDFcwNq07vHYoeCK6B
5RJFIY4Yuk4CORXeElYipz/VyCO2mUgJfHNDs1sCgYEAkS3lBqRwtsHDwPK7D1d4
ktTu4eg7ihpvU0IkDSCJcxKGAljxM4nAY1yU+iCsczmyJORXzv5nWthuwB1Eyav1
Wx5wdDJMq0Aj6ZHrEheIcxA43ddI/Q881yj8iVoqXZsTtOvSoPRo/NXhmpFjkSvK
+ZpMku9mIGpWf4ysuNx7U2ECgYEAlOk+IVFbht7g/4aT99+f0cOJ4ZOMvbPxAASf
KUJ9Jz3w8cye97VAoUXO5WDLgxAwKYpNlbfaOOlc3cmjfUfFygWCavOv1W8h6+Oz
e9zhLh7KJYUcN+PwXlXT4F1ePk5TuvtthgH5Yr+xbqzblSfJY6OoaBq1dk4TbAUU
izerZBUCgYEAn28gG04dByfcyY/crwpRLNVlaA0J93v5H9E/wlEiV1PhEYTdj2S8
PLm9ur3V+kkBSarBur9+rRil0BHvVgC9K6kwMr60JcVT+bmZi0AbPOlPZsp9OPQf
YK5kMSMSbh4t9OUtadogDGI299P6Q9leaU65XRAar96wVsz8X/XdPPc=
-----END RSA PRIVATE KEY-----`

func NewSigningIssuer1KeypairSecret(name string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			v1.TLSCertKey:       issuer1Cert + rootCert,
			v1.TLSPrivateKeyKey: issuer1Key,
		},
	}
}

const issuer2Cert = `-----BEGIN CERTIFICATE-----
MIIDqjCCApKgAwIBAgIUHqm61uyYt2ICGRcZnBSjYaPonuowDQYJKoZIhvcNAQEL
BQAwVzELMAkGA1UEBhMCVUsxCzAJBgNVBAgTAk5BMRUwEwYDVQQKEwxjZXJ0LW1h
bmFnZXIxJDAiBgNVBAMTG2NlcnQtbWFuYWdlciB0ZXN0aW5nIElzc3VlcjAeFw0x
ODExMTUwMDA0MDBaFw0yMzExMTQwMDA0MDBaMF8xCzAJBgNVBAYTAlVLMQswCQYD
VQQIEwJOQTEVMBMGA1UEChMMY2VydC1tYW5hZ2VyMSwwKgYDVQQDEyNjZXJ0LW1h
bmFnZXIgdGVzdGluZyBJc3N1ZXIgTGV2ZWwgMjCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMRm1cYCcHmA7UtF3vISLiob5eh234njNp33nkFWjDsE9Zgi
CIxVb9FBd+rkKn0xkPMke79lmr1kVkmjpAZ0Y0w/IDSEX8JMJvtyuAoS79r0W+rn
dEG5GzJGLswOK0gsvGyl4i8E9a5itUkRa01OETFIiay0iwNMUYnIflm8G/Uu2Jhr
/HSyWND+KLzX5gMDsiv4HdtCsNHstdMwBr4dkiCzpi+N/b2KTggmY84KeVQVpmRc
IVoVr06uc3YTa2mlqrw3qX16d5r9DLYrrq1UT3HXB0PJvvsIjJN8eqKk33Mcbinj
VR1Ywg9QYaJHpBPPxLL0AzNG29SebRLtGvKexoUCAwEAAaNmMGQwDgYDVR0PAQH/
BAQDAgGmMBIGA1UdEwEB/wQIMAYBAf8CAQMwHQYDVR0OBBYEFHp3C+Se1LZMcQ0B
0iycJLvwqo9lMB8GA1UdIwQYMBaAFESJnTHvnJn8qIOb/JD+nw4o0yxnMA0GCSqG
SIb3DQEBCwUAA4IBAQA/lnvr+GnMJDA+Z7MEMRAcqdIScO38LVQNO340jFMcMkmW
YTnyNoEvI4fnCon9Oz2FsFcZp90Gniu01lDLyzR+1SsfFf6zwqGVUV29hidR6BvD
VGLM6SMnbgXUd+RPvAIrHU3BuSF2sRPiw7YqzgNVZQ2dUF+Q+R+Onu5i47CwVFOd
6Dd7xr5+ECaHGyuIH/RsXLvB+2reJ5dEl3oBxiyyzY1oOkt6y4HrB8n90JWPmXIf
9oQ8T+p3PbsFkz667nbVnVCkdAKtU/ZX09S1jGVKsOKszA1qhxFcMy+wkkyHq4Jj
v+q/VgVxL5HzEw4zyKS9Y2lcwhCicMrLKIGt91fQ
-----END CERTIFICATE-----
`

const issuer2Key = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxGbVxgJweYDtS0Xe8hIuKhvl6HbfieM2nfeeQVaMOwT1mCII
jFVv0UF36uQqfTGQ8yR7v2WavWRWSaOkBnRjTD8gNIRfwkwm+3K4ChLv2vRb6ud0
QbkbMkYuzA4rSCy8bKXiLwT1rmK1SRFrTU4RMUiJrLSLA0xRich+Wbwb9S7YmGv8
dLJY0P4ovNfmAwOyK/gd20Kw0ey10zAGvh2SILOmL439vYpOCCZjzgp5VBWmZFwh
WhWvTq5zdhNraaWqvDepfXp3mv0MtiuurVRPcdcHQ8m++wiMk3x6oqTfcxxuKeNV
HVjCD1BhokekE8/EsvQDM0bb1J5tEu0a8p7GhQIDAQABAoIBAFwCzV3RoL3bn8/m
8Pa5e7UwkrogjsM7lkfVTOfRUysHPMPEFfsgv5zqLfL2Z811HjI6wlq9kAvwaNhg
+KQpfKeo3z6bUX1mTdD5Qq09h+8tEa7wNi/gN5SK+ruQW8iZZMEFyfw7N5o2FjYg
GgQCcd2D3TPy9TlbVMvXCRKjJPns4PvWnjcR6YryPCluhnm6t0UEdusAj5baENU5
95XG3e+7ZWzz4uejY778pyV/4yCfMXG9HZInkw9Uj3aNibiP/oKyF8Z0m1tAheLp
SfLH/KxC8sWW/Cn3YFAvq+3fSH3ezeaFNdQFi8L0uGA9h9ucZmKaT5jI1bM9Mj55
Vrsg/wECgYEA7rCQ/NFLtQ6PZNSApxRdWG+67mDrWMuaHho9KB+g0vIzGoxj2+DS
iVlk4F1zVjZ5S8yjSmBm2pxF4ornUdQUs5+iKHJqeweSQenZ3Ylx10rhACfUWhZ+
Zo/mrG30MJs2ceOaYJww1zrcjI3ktFwpZlX95J/e26gGqY8GKA8KaEECgYEA0qUp
3eWvwiTn2ztKEHZ06jNoPB1E3tAA939+W1Cy5VTDH2ZJYDE6lELTgW/7PuS6Auty
cJur3nyIJMQkb2GBqh8jgxb7huDpOkf8kAdPoD9PnmWTisF5XKO5Uv3O2t/xKQNl
pKAC9P1au3uCz8HA2ZbyLqiuXE7SKsIqQmMtbUUCgYArkAwWKDiyBcND+si0NbJH
prSuNwAdB6PMJKvOu98FQPD0wnSjN6gVKzyO+l9Hd8+xdtrCg0+iTG0wyHspYxSY
J+VXjnJCnAIkh4KcvS4Kxf7EoYBPJNXS8CaAh9zOVjWcmZaeVUNQtMx11pvMExn3
NHCPHmJ1Inh8z76m5v/WQQKBgEeQFyYs10ZU9XQ0s1fedp/ucRYjN3efIQT0ioAJ
bY2d+2BahskoUGd4QJTz716RpGRDizCYoo5GrpYXEO3KKZwbUhxCHZfYJ0RGmpZv
9WxStgDxL2vviQShFuAMHE+dzzeI0OpZ9kc3H7EcJ/ffMl55+rNBWWNA4APozSSa
vx8lAoGBAODUjD1S1w/l+OTZWqo+bUvpC58CSioZ+gvNi4KE0h+1ZgLgE1RivQOM
UxwyspRQp2exnQ3hvCpzjhx+ji/FlhK86lspGjyZqTd+ifa/tO51+tvU217/XDtx
JypkAFhZ398YzhuqsRbFNMFnxA6QT+YFsqjT+R0vSFM8n2qptJHB
-----END RSA PRIVATE KEY-----`

func NewSigningIssuer2KeypairSecret(name string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			v1.TLSCertKey:       issuer2Cert + issuer1Cert + rootCert,
			v1.TLSPrivateKeyKey: issuer2Key,
		},
	}
}
