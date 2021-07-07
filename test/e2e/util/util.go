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

package util

// TODO: we should break this file apart into separate more sane/reusable parts

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/gateway-api/apis/v1alpha1"
	gwapiv1alpha1 "sigs.k8s.io/gateway-api/apis/v1alpha1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	intscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
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

func WaitForIssuerStatusFunc(client clientset.IssuerInterface, name string, fn func(*v1.Issuer) (bool, error)) error {
	return wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			issuer, err := client.Get(context.TODO(), name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}
			return fn(issuer)
		})
}

// WaitForIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func WaitForIssuerCondition(client clientset.IssuerInterface, name string, condition v1.IssuerCondition) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			log.Logf("Waiting for issuer %v condition %#v", name, condition)
			issuer, err := client.Get(context.TODO(), name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}

			return apiutil.IssuerHasCondition(issuer, condition), nil
		},
	)
	return wrapErrorWithIssuerStatusCondition(client, pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithIssuerStatusCondition(client clientset.IssuerInterface, pollErr error, name string, conditionType v1.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	issuer, err := client.Get(context.TODO(), name, metav1.GetOptions{})
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
func WaitForClusterIssuerCondition(client clientset.ClusterIssuerInterface, name string, condition v1.IssuerCondition) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, time.Minute,
		func() (bool, error) {
			log.Logf("Waiting for clusterissuer %v condition %#v", name, condition)
			issuer, err := client.Get(context.TODO(), name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting ClusterIssuer %v: %v", name, err)
			}

			return apiutil.IssuerHasCondition(issuer, condition), nil
		},
	)
	return wrapErrorWithClusterIssuerStatusCondition(client, pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithClusterIssuerStatusCondition(client clientset.ClusterIssuerInterface, pollErr error, name string, conditionType v1.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	issuer, err := client.Get(context.TODO(), name, metav1.GetOptions{})
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
func WaitForCertificateCondition(client clientset.CertificateInterface, name string, condition v1.CertificateCondition, timeout time.Duration) (*v1.Certificate, error) {
	var certificate *v1.Certificate = nil
	pollErr := wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			log.Logf("Waiting for Certificate %v condition %v=%v", name, condition.Type, condition.Status)
			certificate, err := client.Get(context.TODO(), name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			if !apiutil.CertificateHasCondition(certificate, condition) {
				log.Logf("Expected Certificate %v condition %v=%v but it has: %v", name, condition.Type, condition.Status, condition.ObservedGeneration, certificate.Status.Conditions)
				return false, nil
			}
			return true, nil
		},
	)
	return certificate, wrapErrorWithCertificateStatusCondition(client, pollErr, name, condition.Type)
}

// WaitForCertificateConditionWithObservedGeneration waits for the status of the named Certificate to contain
// a condition whose type and status matches the supplied one.
func WaitForCertificateConditionWithObservedGeneration(client clientset.CertificateInterface, name string, condition v1.CertificateCondition, timeout time.Duration) (*v1.Certificate, error) {
	var certificate *v1.Certificate = nil
	pollErr := wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			log.Logf("Waiting for Certificate %v condition %v=%v", name, condition.Type, condition.Status)
			certificate, err := client.Get(context.TODO(), name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}
			if !apiutil.CertificateHasConditionWithObservedGeneration(certificate, condition) {
				log.Logf("Expected Certificate %v condition %v=%v (generation >= %v) but it has: %v", name, condition.Type, condition.Status, condition.ObservedGeneration, certificate.Status.Conditions)
				return false, nil
			}
			return true, nil
		},
	)
	return certificate, wrapErrorWithCertificateStatusCondition(client, pollErr, name, condition.Type)
}

// WaitForCertificateEvent waits for an event on the named Certificate to contain
// an event reason matches the supplied one.
func WaitForCertificateEvent(client kubernetes.Interface, cert *v1.Certificate, reason string, timeout time.Duration) error {
	return wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			log.Logf("Waiting for Certificate event %v reason %#v", cert.Name, reason)
			evts, err := client.CoreV1().Events(cert.Namespace).Search(intscheme.Scheme, cert)
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", cert.Name, err)
			}

			return hasEvent(evts, reason), nil
		},
	)
}

func hasEvent(events *corev1.EventList, reason string) bool {
	for _, evt := range events.Items {
		if evt.Reason == reason {
			return true
		}
	}
	return false
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithCertificateStatusCondition(client clientset.CertificateInterface, pollErr error, name string, conditionType v1.CertificateConditionType) error {
	if pollErr == nil {
		return nil
	}

	certificate, err := client.Get(context.TODO(), name, metav1.GetOptions{})
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
			_, err := client.Get(context.TODO(), name, metav1.GetOptions{})
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
			_, err := client.Get(context.TODO(), name, metav1.GetOptions{})
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

// Deprecated: use test/unit/gen/Certificate in future
func NewCertManagerBasicCertificate(name, secretName, issuerName string, issuerKind string, duration, renewBefore *metav1.Duration, dnsNames ...string) *v1.Certificate {
	cn := "test.domain.com"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	return &v1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1.CertificateSpec{
			CommonName: cn,
			DNSNames:   dnsNames,
			Subject: &v1.X509Subject{
				Organizations: []string{"test-org"},
			},
			SecretName:  secretName,
			Duration:    duration,
			RenewBefore: renewBefore,
			PrivateKey:  &v1.CertificatePrivateKey{},
			IssuerRef: cmmeta.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
}

// Deprecated: use test/unit/gen/CertificateRequest in future
func NewCertManagerBasicCertificateRequest(name, issuerName string, issuerKind string, duration *metav1.Duration,
	dnsNames []string, ips []net.IP, uris []string, keyAlgorithm x509.PublicKeyAlgorithm) (*v1.CertificateRequest, crypto.Signer, error) {
	cn := "test.domain.com"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}

	var parsedURIs []*url.URL
	for _, uri := range uris {
		parsed, err := url.Parse(uri)
		if err != nil {
			return nil, nil, err
		}
		parsedURIs = append(parsedURIs, parsed)
	}

	var sk crypto.Signer
	var signatureAlgorithm x509.SignatureAlgorithm
	var err error

	switch keyAlgorithm {
	case x509.RSA:
		sk, err = pki.GenerateRSAPrivateKey(2048)
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = x509.SHA256WithRSA
	case x509.ECDSA:
		sk, err = pki.GenerateECPrivateKey(pki.ECCurve256)
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = x509.ECDSAWithSHA256
	case x509.Ed25519:
		sk, err = pki.GenerateEd25519PrivateKey()
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = x509.PureEd25519
	default:
		return nil, nil, fmt.Errorf("unrecognised key algorithm: %s", err)
	}

	csr := &x509.CertificateRequest{
		Version:            3,
		SignatureAlgorithm: signatureAlgorithm,
		PublicKeyAlgorithm: keyAlgorithm,
		PublicKey:          sk.Public(),
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames:    dnsNames,
		IPAddresses: ips,
		URIs:        parsedURIs,
	}

	csrBytes, err := pki.EncodeCSR(csr, sk)
	if err != nil {
		return nil, nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})

	return &v1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1.CertificateRequestSpec{
			Duration: duration,
			Request:  csrPEM,
			IssuerRef: cmmeta.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}, sk, nil
}

func NewCertManagerVaultCertificate(name, secretName, issuerName string, issuerKind string, duration, renewBefore *metav1.Duration) *v1.Certificate {
	return &v1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1.CertificateSpec{
			CommonName:  "test.domain.com",
			SecretName:  secretName,
			Duration:    duration,
			RenewBefore: renewBefore,
			IssuerRef: cmmeta.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
}

func NewIngress(name, secretName string, annotations map[string]string, dnsNames ...string) *networkingv1beta1.Ingress {
	return &networkingv1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: networkingv1beta1.IngressSpec{
			TLS: []networkingv1beta1.IngressTLS{
				{
					Hosts:      dnsNames,
					SecretName: secretName,
				},
			},
			Rules: []networkingv1beta1.IngressRule{
				{
					Host: dnsNames[0],
					IngressRuleValue: networkingv1beta1.IngressRuleValue{
						HTTP: &networkingv1beta1.HTTPIngressRuleValue{
							Paths: []networkingv1beta1.HTTPIngressPath{
								{
									Path: "/",
									Backend: networkingv1beta1.IngressBackend{
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

func NewGateway(gatewayName, ns, secretName string, annotations map[string]string, dnsNames ...string) (*gwapiv1alpha1.Gateway, *gwapiv1alpha1.HTTPRoute) {
	var hostnames []gwapiv1alpha1.Hostname
	for _, dnsName := range dnsNames {
		hostnames = append(hostnames, gwapiv1alpha1.Hostname(dnsName))
	}

	return &gwapiv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:        gatewayName,
				Annotations: annotations,
			},
			Spec: gwapiv1alpha1.GatewaySpec{
				GatewayClassName: "istio",
				Listeners: []v1alpha1.Listener{{
					Routes: gwapiv1alpha1.RouteBindingSelector{
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
							"gw": gatewayName,
						}},
					},
					Port:     gwapiv1alpha1.PortNumber(80),
					Hostname: (*gwapiv1alpha1.Hostname)(&dnsNames[0]),
					TLS: &gwapiv1alpha1.GatewayTLSConfig{
						CertificateRef: &gwapiv1alpha1.LocalObjectReference{
							Name:  secretName,
							Kind:  "Secret",
							Group: "core",
						},
					},
				}},
			},
		},
		&gwapiv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:        gatewayName,
				Annotations: annotations,
				Labels: map[string]string{
					"gw": gatewayName,
				},
			},
			Spec: gwapiv1alpha1.HTTPRouteSpec{
				Gateways: &gwapiv1alpha1.RouteGateways{
					GatewayRefs: []gwapiv1alpha1.GatewayReference{{
						Name:      gatewayName,
						Namespace: ns,
					}},
				},
				Hostnames: hostnames,
				Rules: []gwapiv1alpha1.HTTPRouteRule{{
					Matches: []gwapiv1alpha1.HTTPRouteMatch{{
						Path: &gwapiv1alpha1.HTTPPathMatch{
							Type:  ptrPathMatch(gwapiv1alpha1.PathMatchExact),
							Value: ptrStr("/"),
						},
					}},
					ForwardTo: []gwapiv1alpha1.HTTPRouteForwardTo{{
						ServiceName: ptrStr("dummy-service"),
						Port:        ptrPort(80),
					}},
				}},
			},
		}
}
func ptrPathMatch(p gwapiv1alpha1.PathMatchType) *gwapiv1alpha1.PathMatchType {
	return &p
}

func ptrStr(s string) *string {
	return &s
}

func ptrPort(port int32) *gwapiv1alpha1.PortNumber {
	p := gwapiv1alpha1.PortNumber(port)
	return &p
}
