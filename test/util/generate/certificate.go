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

type CertificateConfig struct {
	// metadata
	Name, Namespace string

	// common parameters
	IssuerName, IssuerKind string
	SecretName             string
	CommonName             string
	DNSNames               []string
	Duration               *metav1.Duration
	RenewBefore            *metav1.Duration

	// ACME parameters
	SolverConfig v1alpha1.SolverConfig
}

func Certificate(cfg CertificateConfig) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.Name,
			Namespace: cfg.Namespace,
		},
		Spec: v1alpha1.CertificateSpec{
			Duration:    cfg.Duration,
			RenewBefore: cfg.RenewBefore,
			SecretName:  cfg.SecretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: cfg.IssuerName,
				Kind: cfg.IssuerKind,
			},
			CommonName: cfg.CommonName,
			DNSNames:   cfg.DNSNames,
			ACME: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.DomainSolverConfig{
					{
						Domains:      cfg.DNSNames,
						SolverConfig: cfg.SolverConfig,
					},
				},
			},
		},
		Status: v1alpha1.CertificateStatus{},
	}
}
