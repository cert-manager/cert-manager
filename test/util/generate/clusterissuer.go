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

package generate

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type ClusterIssuerConfig struct {
	Name, Namespace string

	ACMESkipTLSVerify                         bool
	ACMEServer, ACMEEmail, ACMEPrivateKeyName string
	HTTP01                                    *v1alpha1.ACMEIssuerHTTP01Config
	DNS01                                     *v1alpha1.ACMEIssuerDNS01Config
}

func ClusterIssuer(cfg ClusterIssuerConfig) *v1alpha1.ClusterIssuer {
	return &v1alpha1.ClusterIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterIssuer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.Name,
			Namespace: cfg.Namespace,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: &v1alpha1.ACMEIssuer{
					SkipTLSVerify: cfg.ACMESkipTLSVerify,
					Server:        cfg.ACMEServer,
					Email:         cfg.ACMEEmail,
					PrivateKey: v1alpha1.SecretKeySelector{
						LocalObjectReference: v1alpha1.LocalObjectReference{
							Name: cfg.ACMEPrivateKeyName,
						},
					},
					HTTP01: cfg.HTTP01,
					DNS01:  cfg.DNS01,
				},
			},
		},
	}
}
