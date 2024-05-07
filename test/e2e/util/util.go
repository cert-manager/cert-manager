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
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	gwapiv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func CertificateOnlyValidForDomains(cert *x509.Certificate, commonName string, dnsNames ...string) bool {
	if commonName != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, dnsNames) {
		return false
	}
	return true
}

func WaitForIssuerStatusFunc(ctx context.Context, client clientset.IssuerInterface, name string, fn func(*v1.Issuer) (bool, error)) error {
	return wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		issuer, err := client.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
		}
		return fn(issuer)
	})
}

// WaitForIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func WaitForIssuerCondition(ctx context.Context, client clientset.IssuerInterface, name string, condition v1.IssuerCondition) error {
	logf, done := log.LogBackoff()
	defer done()
	pollErr := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		logf("Waiting for issuer %v condition %#v", name, condition)
		issuer, err := client.Get(ctx, name, metav1.GetOptions{})
		if nil != err {
			return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
		}

		return apiutil.IssuerHasCondition(issuer, condition), nil
	})
	return wrapErrorWithIssuerStatusCondition(ctx, client, pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithIssuerStatusCondition(ctx context.Context, client clientset.IssuerInterface, pollErr error, name string, conditionType v1.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	issuer, err := client.Get(ctx, name, metav1.GetOptions{})
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
func WaitForClusterIssuerCondition(ctx context.Context, client clientset.ClusterIssuerInterface, name string, condition v1.IssuerCondition) error {
	logf, done := log.LogBackoff()
	defer done()
	pollErr := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		logf("Waiting for clusterissuer %v condition %#v", name, condition)
		issuer, err := client.Get(ctx, name, metav1.GetOptions{})
		if nil != err {
			return false, fmt.Errorf("error getting ClusterIssuer %v: %v", name, err)
		}

		return apiutil.IssuerHasCondition(issuer, condition), nil
	})
	return wrapErrorWithClusterIssuerStatusCondition(ctx, client, pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithClusterIssuerStatusCondition(ctx context.Context, client clientset.ClusterIssuerInterface, pollErr error, name string, conditionType v1.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	issuer, err := client.Get(ctx, name, metav1.GetOptions{})
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

// WaitForCRDToNotExist waits for the CRD with the given name to no
// longer exist.
func WaitForCRDToNotExist(ctx context.Context, client apiextensionsv1.CustomResourceDefinitionInterface, name string) error {
	logf, done := log.LogBackoff()
	defer done()
	return wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, time.Minute, true, func(ctx context.Context) (bool, error) {
		logf("Waiting for CRD %v to not exist", name)
		_, err := client.Get(ctx, name, metav1.GetOptions{})
		if nil == err {
			return false, nil
		}

		if errors.IsNotFound(err) {
			return true, nil
		}

		return false, nil
	})
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
		Version:            0,
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

func NewIngress(name, secretName string, annotations map[string]string, dnsNames ...string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      dnsNames,
					SecretName: secretName,
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: dnsNames[0],
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: pathTypePrefix(),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "somesvc",
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
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

func NewV1Beta1Ingress(name, secretName string, annotations map[string]string, dnsNames ...string) *networkingv1beta1.Ingress {
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
										ServiceName: "somesvc",
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

func pathTypePrefix() *networkingv1.PathType {
	p := networkingv1.PathTypePrefix
	return &p
}

// NewGateway creates a new test Gateway. There is no Gateway controller
// watching the 'foo' gateway class, so this Gateway will not be used to
// actually route traffic, but can be used to test cert-manager controllers that
// sync Gateways, such as gateway-shim.
func NewGateway(gatewayName, ns, secretName string, annotations map[string]string, dnsNames ...string) *gwapiv1beta1.Gateway {

	return &gwapiv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:        gatewayName,
			Annotations: annotations,
		},
		Spec: gwapiv1beta1.GatewaySpec{
			GatewayClassName: "foo",
			Listeners: []gwapiv1beta1.Listener{{
				AllowedRoutes: &gwapiv1beta1.AllowedRoutes{
					Namespaces: &gwapiv1beta1.RouteNamespaces{
						From: func() *gwapiv1beta1.FromNamespaces { f := gwapiv1beta1.NamespacesFromSame; return &f }(),
						Selector: &metav1.LabelSelector{MatchLabels: map[string]string{
							"gw": gatewayName,
						}},
					},
					Kinds: nil,
				},
				Name:     "acme-solver",
				Protocol: gwapiv1beta1.TLSProtocolType,
				Port:     gwapiv1beta1.PortNumber(443),
				Hostname: (*gwapiv1beta1.Hostname)(&dnsNames[0]),
				TLS: &gwapiv1beta1.GatewayTLSConfig{
					CertificateRefs: []gwapiv1beta1.SecretObjectReference{
						{
							Kind:      func() *gwapiv1beta1.Kind { k := gwapiv1beta1.Kind("Secret"); return &k }(),
							Name:      gwapiv1beta1.ObjectName(secretName),
							Group:     func() *gwapiv1beta1.Group { g := gwapiv1beta1.Group(corev1.GroupName); return &g }(),
							Namespace: (*gwapiv1beta1.Namespace)(&ns),
						},
					},
				},
			}},
		},
	}
}

// HasIngresses lets you know if an API exists in the discovery API
// calling this function always performs a request to the API server.
func HasIngresses(d discovery.DiscoveryInterface, groupVersion string) bool {
	resourceList, err := d.ServerResourcesForGroupVersion(groupVersion)
	if err != nil {
		return false
	}
	for _, r := range resourceList.APIResources {
		if r.Kind == "Ingress" {
			return true
		}
	}
	return false
}
