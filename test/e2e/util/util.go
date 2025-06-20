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
	"fmt"
	"net"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwapiv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
	"github.com/cert-manager/cert-manager/test/unit/gen"

	. "github.com/onsi/gomega"
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
func NewCertManagerBasicCertificateRequest(
	name, namespace string,
	issuerName, issuerKind string,
	duration *metav1.Duration,
	dnsNames []string, ips []net.IP, uris []string,
	keyAlgorithm x509.PublicKeyAlgorithm,
) (*v1.CertificateRequest, crypto.Signer, error) {
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

	csrPEM, sk, err := gen.CSR(keyAlgorithm,
		gen.SetCSRCommonName(cn),
		gen.SetCSRDNSNames(dnsNames...),
		gen.SetCSRIPAddresses(ips...),
		gen.SetCSRURIs(parsedURIs...),
	)
	if err != nil {
		return nil, nil, err
	}

	return gen.CertificateRequest(name,
		gen.SetCertificateRequestNamespace(namespace),
		gen.SetCertificateRequestDuration(duration),
		gen.SetCertificateRequestCSR(csrPEM),
		gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
			Name: issuerName,
			Kind: issuerKind,
		}),
	), sk, nil
}

func NewCertManagerVaultCertificate(name, secretName, issuerName string, issuerKind string, duration *metav1.Duration, renewBefore *metav1.Duration) *v1.Certificate {
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
										ServicePort: intstr.FromInt32(80),
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

// AddFinalizer will add a finalizer to the given object, it is designed to
// be used within Eventually calls so conflicts get resolved
func AddFinalizer(g Gomega, ctx context.Context, cli client.Client, obj client.Object, finalizer string) {
	key := client.ObjectKeyFromObject(obj)
	g.Expect(cli.Get(ctx, key, obj)).NotTo(HaveOccurred(), "failed to get %T", obj)

	if controllerutil.AddFinalizer(obj, finalizer) {
		g.Expect(cli.Update(ctx, obj)).NotTo(HaveOccurred(), "failed to update %T", obj)
	}
}

// RemoveFinalizer will remove a finalizer to the given object, it is designed to
// be used within Eventually calls so conflicts get resolved. If the object
// does not exist then no error is returned as removing the finalizer may cause
// deletion
func RemoveFinalizer(g Gomega, ctx context.Context, cli client.Client, obj client.Object, finalizer string) {
	key := client.ObjectKeyFromObject(obj)

	if err := cli.Get(ctx, key, obj); err != nil {
		g.Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred(), "failed to get %T", obj)
		return
	}

	if controllerutil.RemoveFinalizer(obj, finalizer) {
		g.Expect(client.IgnoreNotFound(cli.Update(ctx, obj))).NotTo(HaveOccurred(), "failed to update %T", obj)
	}
}

// ObjectPtrConstraint is a constraint used for ensuring T is a both a pointer
// and implements client.Object
type ObjectPtrConstraint[T any] interface {
	*T
	client.Object
}

// ObjectListPtrConstraint is a constraint used for ensuring T is a both a
// pointer and implements client.ObjectList
type ObjectListPtrConstraint[T any] interface {
	*T
	client.ObjectList
}

// ListMatchingPredicates will list the objects that match a set of predicates
func ListMatchingPredicates[O any, OL any, P ObjectPtrConstraint[O], PL ObjectListPtrConstraint[OL]](g Gomega, ctx context.Context, cli client.Client, predicates ...predicate.Func) []O {
	list := PL(new(OL))
	g.Expect(cli.List(ctx, list)).ToNot(HaveOccurred(), "failed to list objects")

	// Evaluate predicates
	funcs := predicate.Funcs(predicates)
	out := make([]O, 0)
	err := meta.EachListItem(list, func(o runtime.Object) error {
		if funcs.Evaluate(o) {
			out = append(out, *(o.(P)))
		}
		return nil
	})
	Expect(err).NotTo(HaveOccurred(), "failed to iterate over objects")

	return out
}
