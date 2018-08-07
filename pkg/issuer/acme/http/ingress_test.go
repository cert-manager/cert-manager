package http

import (
	"fmt"
	"reflect"
	"testing"

	"k8s.io/api/extensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/util/generate"
)

func TestGetIngressesForChallenge(t *testing.T) {
	const createdIngressKey = "createdIngress"
	tests := map[string]solverFixture{
		"should return one ingress that matches": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:      "test",
				Namespace: defaultTestNamespace,
				DNSNames:  []string{"example.com"},
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", s.Challenge)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdIngressKey] = ing
				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				createdIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)
				resp := args[0].([]*v1beta1.Ingress)
				if len(resp) != 1 {
					s.f.T.Errorf("expected one ingress to be returned, but got %d", len(resp))
					s.f.T.Fail()
					return
				}
				if !reflect.DeepEqual(resp[0], createdIngress) {
					s.f.T.Errorf("Expected %v to equal %v", resp[0], createdIngress)
				}
			},
		},
		"should not return an ingress for the same certificate but different domain": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:      "test",
				Namespace: defaultTestNamespace,
				DNSNames:  []string{"example.com"},
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(s *solverFixture) {
				_, err := s.Solver.createIngress(s.Certificate, "fakeservice", v1alpha1.ACMEOrderChallenge{
					Domain: "notexample.com",
				})
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}

				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				resp := args[0].([]*v1beta1.Ingress)
				if len(resp) != 0 {
					s.f.T.Errorf("expected zero ingresses to be returned, but got %d", len(resp))
					s.f.T.Fail()
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getIngressesForChallenge(test.Certificate, test.Challenge)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t, resp, err)
		})
	}
}

func TestCleanupIngresses(t *testing.T) {
	const createdIngressKey = "createdIngress"
	tests := map[string]solverFixture{
		"should delete ingress resource": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testurl",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						IngressClass: strPtr("nginx"),
					},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "abcd",
			},
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", s.Challenge)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdIngressKey] = ing
				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				createdIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)
				ing, err := s.f.KubeClient().ExtensionsV1beta1().Ingresses(s.Certificate.Namespace).Get(createdIngress.Name, metav1.GetOptions{})
				if err != nil && !apierrors.IsNotFound(err) {
					s.f.T.Errorf("error when getting test ingress, expected 'not found' but got: %v", err)
				}
				if !apierrors.IsNotFound(err) {
					s.f.T.Errorf("expected ingress %q to not exist, but the resource was found: %+v", createdIngress.Name, ing)
				}
			},
		},
		"should not delete ingress resources without appropriate labels": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testurl",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						IngressClass: strPtr("nginx"),
					},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "abcd",
			},
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", v1alpha1.ACMEOrderChallenge{
					Domain: "notexample.com",
					Token:  "abcd",
				})
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdIngressKey] = ing
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				createdIngress := s.testResources[createdIngressKey].(*v1beta1.Ingress)
				_, err := s.f.KubeClient().ExtensionsV1beta1().Ingresses(s.Certificate.Namespace).Get(createdIngress.Name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					s.f.T.Errorf("expected ingress resource %q to not be deleted, but it was deleted", createdIngress.Name)
				}
				if err != nil {
					s.f.T.Errorf("error getting ingress resource: %v", err)
				}
			},
		},
		"should return an error if a delete fails": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testurl",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{
						IngressClass: strPtr("nginx"),
					},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "abcd",
			},
			Err: true,
			PreFn: func(s *solverFixture) {
				s.f.KubeClient().PrependReactor("delete", "ingresses", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("simulated error")
				})
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", s.Challenge)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdIngressKey] = ing
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			err := test.Solver.cleanupIngresses(test.Certificate, test.Challenge)
			if err != nil && !test.Err {
				t.Errorf("Expected function to not error, but got: %v", err)
			}
			if err == nil && test.Err {
				t.Errorf("Expected function to get an error, but got: %v", err)
			}
			test.Finish(t)
		})
	}
}
