package http

import (
	"reflect"
	"testing"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/util/generate"
)

func TestEnsurePod(t *testing.T) {
	const createdPodKey = "createdPod"
	tests := map[string]solverFixture{
		"should return an existing pod if one already exists": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "token",
				Key:    "key",
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createPod(s.Certificate, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				s.testResources[createdPodKey] = ing

				// TODO: replace this with expectedActions to make sure no other actions are performed
				// create a reactor that fails the test if a pod is created
				s.Builder.FakeKubeClient().PrependReactor("create", "pods", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					t.Errorf("ensurePod should not create a pod if one already exists")
					t.Fail()
					return false, ret, nil
				})

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdPod := s.testResources[createdPodKey].(*v1.Pod)
				resp := args[0].(*v1.Pod)
				if resp == nil {
					t.Errorf("unexpected pod = nil")
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp, createdPod) {
					t.Errorf("Expected %v to equal %v", resp, createdPod)
				}
			},
		},
		"should create a new pod if one does not exist": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "token",
				Key:    "key",
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				expectedPod := s.Solver.buildPod(s.Certificate, s.Challenge)
				// create a reactor that fails the test if a pod is created
				s.Builder.FakeKubeClient().PrependReactor("create", "pods", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					pod := action.(coretesting.CreateAction).GetObject().(*v1.Pod)
					// clear pod name as we don't know it yet in the expectedPod
					pod.Name = ""
					if !reflect.DeepEqual(pod, expectedPod) {
						t.Errorf("Expected %v to equal %v", pod, expectedPod)
					}
					return false, ret, nil
				})

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].(*v1.Pod)
				err := args[1]
				if resp == nil && err == nil {
					t.Errorf("unexpected pod = nil")
					t.Fail()
					return
				}
				pods, err := s.Solver.podLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("unexpected error listing pods: %v", err)
					t.Fail()
					return
				}
				if len(pods) != 1 {
					t.Errorf("unexpected %d pods in lister: %+v", len(pods), pods)
					t.Fail()
					return
				}
				if !reflect.DeepEqual(pods[0], resp) {
					t.Errorf("Expected %v to equal %v", pods[0], resp)
				}
			},
		},
		"should clean up if multiple pods exist": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
				Token:  "token",
				Key:    "key",
			},
			Err: true,
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createPod(s.Certificate, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}
				_, err = s.Solver.createPod(s.Certificate, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				pods, err := s.Solver.podLister.List(labels.NewSelector())
				if err != nil {
					t.Errorf("error listing pods: %v", err)
					t.Fail()
					return
				}
				if len(pods) != 0 {
					t.Errorf("expected pods to have been cleaned up, but there were %d pods left", len(pods))
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.ensurePod(test.Certificate, test.Challenge)
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

func TestGetPodsForCertificate(t *testing.T) {
	const createdPodKey = "createdPod"
	tests := map[string]solverFixture{
		"should return one pod that matches": {
			Certificate: generate.Certificate(generate.CertificateConfig{
				Name:         "test",
				Namespace:    defaultTestNamespace,
				DNSNames:     []string{"example.com"},
				ACMEOrderURL: "testURL",
				SolverConfig: v1alpha1.SolverConfig{
					HTTP01: &v1alpha1.HTTP01SolverConfig{},
				},
			}),
			Challenge: v1alpha1.ACMEOrderChallenge{
				Domain: "example.com",
			},
			PreFn: func(t *testing.T, s *solverFixture) {
				ing, err := s.Solver.createPod(s.Certificate, s.Challenge)
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.testResources[createdPodKey] = ing
				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				createdPod := s.testResources[createdPodKey].(*v1.Pod)
				resp := args[0].([]*v1.Pod)
				if len(resp) != 1 {
					t.Errorf("expected one pod to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
				if !reflect.DeepEqual(resp[0], createdPod) {
					t.Errorf("Expected %v to equal %v", resp[0], createdPod)
				}
			},
		},
		"should not return a pod for the same certificate but different domain": {
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
			PreFn: func(t *testing.T, s *solverFixture) {
				_, err := s.Solver.createPod(s.Certificate, v1alpha1.ACMEOrderChallenge{
					Domain: "notexample.com",
				})
				if err != nil {
					t.Errorf("error preparing test: %v", err)
				}

				s.Builder.Sync()
			},
			CheckFn: func(t *testing.T, s *solverFixture, args ...interface{}) {
				resp := args[0].([]*v1.Pod)
				if len(resp) != 0 {
					t.Errorf("expected zero pods to be returned, but got %d", len(resp))
					t.Fail()
					return
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Setup(t)
			resp, err := test.Solver.getPodsForChallenge(test.Certificate, test.Challenge)
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
