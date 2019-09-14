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

package validation

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func TestValidateClusterIssuer(t *testing.T) {
	acmeIssuer := &v1alpha1.ACMEIssuer{
		Email:      "valid-email",
		Server:     "valid-server",
		PrivateKey: validSecretKeyRef,
		Solvers: []v1alpha1.ACMEChallengeSolver{
			{
				HTTP01: &v1alpha1.ACMEChallengeSolverHTTP01{
					Ingress: &v1alpha1.ACMEChallengeSolverHTTP01Ingress{
						PodTemplate: &v1alpha1.ACMEChallengeSolverHTTP01IngressPodTemplate{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: "the_namespace",
								Labels: map[string]string{
									"valid_to_contain": "labels",
								},
								Annotations: map[string]string{
									"valid_to_contain": "annotations",
								},
							},
						},
					},
				},
			},
		},
		HTTP01: &v1alpha1.ACMEIssuerHTTP01Config{
			ServiceType: corev1.ServiceType("NodePort"),
		},
	}

	issuer := &v1alpha1.ClusterIssuer{
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: acmeIssuer,
			},
		},
	}

	errs := ValidateClusterIssuer(issuer)
	if 0 != len(errs) {
		t.Errorf("No errors expected, but got %v", errs)
	}
}
