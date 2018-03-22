package http

import (
	"fmt"
	"reflect"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/test/util/generate"
)

func TestGetIngressesForCertificate(t *testing.T) {
	tests := map[string]solverFixture{
		"should return one ingress that matches": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:      "test",
				Namespace: defaultTestNamespace,
				DNSNames:  []string{"example.com"},
			}),
			Domain: "example.com",
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", s.Domain, s.Token, *s.Certificate.Spec.ACME.ConfigForDomain(s.Domain).HTTP01)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}

				s.createdIngress = ing
				s.f.Sync()
			},
			CheckFn: func(s *solverFixture) {
				ing, err := s.f.KubeClient().ExtensionsV1beta1().Ingresses(s.Namespace).List(metav1.ListOptions{})
				if err != nil {
					s.f.T.Errorf("error listing ingresses: %v", err)
					s.f.T.Fail()
				}
				if len(ing.Items) != 1 {
					s.f.T.Errorf("expected one ingress to be returned, but got %d", len(ing.Items))
					s.f.T.Fail()
					return
				}
				if !reflect.DeepEqual(&ing.Items[0], s.createdIngress) {
					s.f.T.Errorf("Expected %v to equal %v", ing.Items[0], s.createdIngress)
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			_, err := test.Solver.getIngressesForCertificate(test.Certificate, test.Domain)
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

func TestCleanupIngresses(t *testing.T) {
	tests := map[string]solverFixture{
		"should delete ingress resource": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:             "test",
				Namespace:        defaultTestNamespace,
				DNSNames:         []string{"example.com"},
				ACMEOrderURL:     "testurl",
				ACMEIngressClass: strPtr("nginx"),
			}),
			Domain: "example.com",
			Token:  "abcd",
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", s.Domain, s.Token, *s.Certificate.Spec.ACME.ConfigForDomain(s.Domain).HTTP01)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}
				s.createdIngress = ing
				s.f.Sync()
			},
			CheckFn: func(s *solverFixture) {
				ing, err := s.f.KubeClient().ExtensionsV1beta1().Ingresses(s.Certificate.Namespace).Get(s.createdIngress.Name, metav1.GetOptions{})
				if err != nil && !apierrors.IsNotFound(err) {
					s.f.T.Errorf("error when getting test ingress, expected 'not found' but got: %v", err)
				}
				if !apierrors.IsNotFound(err) {
					s.f.T.Errorf("expected ingress %q to not exist, but the resource was found: %+v", s.createdIngress.Name, ing)
				}
			},
		},
		"should not delete ingress resources without appropriate labels": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:             "test",
				Namespace:        defaultTestNamespace,
				DNSNames:         []string{"example.com"},
				ACMEOrderURL:     "testurl",
				ACMEIngressClass: strPtr("nginx"),
			}),
			Domain: "example.com",
			Token:  "abcd",
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", "notthetestdomain.com", s.Token, *s.Certificate.Spec.ACME.ConfigForDomain(s.Domain).HTTP01)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}
				s.createdIngress = ing
			},
			CheckFn: func(s *solverFixture) {
				_, err := s.f.KubeClient().ExtensionsV1beta1().Ingresses(s.Certificate.Namespace).Get(s.createdIngress.Name, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					s.f.T.Errorf("expected ingress resource %q to not be deleted, but it was deleted", s.createdIngress.Name)
				}
				if err != nil {
					s.f.T.Errorf("error getting ingress resource: %v", err)
				}
			},
		},
		"should return an error if a delete fails": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:             "test",
				Namespace:        defaultTestNamespace,
				DNSNames:         []string{"example.com"},
				ACMEOrderURL:     "testurl",
				ACMEIngressClass: strPtr("nginx"),
			}),
			Domain: "example.com",
			Token:  "abcd",
			Err:    true,
			PreFn: func(s *solverFixture) {
				s.f.KubeClient().PrependReactor("delete", "ingresses", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("simulated error")
				})
				ing, err := s.Solver.createIngress(s.Certificate, "fakeservice", "example.com", s.Token, *s.Certificate.Spec.ACME.ConfigForDomain(s.Domain).HTTP01)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}
				s.createdIngress = ing
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			err := test.Solver.cleanupIngresses(test.Certificate, test.Domain, test.Token)
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
