package http

import (
	"reflect"
	"testing"

	"k8s.io/api/core/v1"

	"github.com/jetstack/cert-manager/test/util/generate"
)

func TestGetPodsForCertificate(t *testing.T) {
	const createdPodKey = "createdPod"
	tests := map[string]solverFixture{
		"should return one pod that matches": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
			}),
			Domain: "example.com",
			PreFn: func(s *solverFixture) {
				ing, err := s.Solver.createPod(s.Certificate, s.Domain, s.Token, s.Key)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdPodKey] = ing
				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				createdPod := s.testResources[createdPodKey].(*v1.Pod)
				resp := args[0].([]*v1.Pod)
				if len(resp) != 1 {
					s.f.T.Errorf("expected one pod to be returned, but got %d", len(resp))
					s.f.T.Fail()
					return
				}
				if !reflect.DeepEqual(resp[0], createdPod) {
					s.f.T.Errorf("Expected %v to equal %v", resp[0], createdPod)
				}
			},
		},
		"should not return a pod for the same certificate but different domain": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:      "test",
				Namespace: defaultTestNamespace,
				DNSNames:  []string{"example.com"},
			}),
			Domain: "example.com",
			PreFn: func(s *solverFixture) {
				_, err := s.Solver.createPod(s.Certificate, "invaliddomain", s.Token, s.Key)
				if err != nil {
					s.f.T.Errorf("error preparing test: %v", err)
				}

				s.f.Sync()
			},
			CheckFn: func(s *solverFixture, args ...interface{}) {
				resp := args[0].([]*v1.Pod)
				if len(resp) != 0 {
					s.f.T.Errorf("expected zero pods to be returned, but got %d", len(resp))
					s.f.T.Fail()
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getPodsForCertificate(test.Certificate, test.Domain)
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
