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

package ctl

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/renew"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/integration/framework"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// TestCtlRenew tests the renewal logic of the ctl CLI command against the
// cert-manager Issuing controller.
func TestCtlRenew(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build clients
	kubeClient, _, cmCl, _ := framework.NewClients(t, config)

	var (
		crt1Name = "testcrt-1"
		crt2Name = "testcrt-2"
		crt3Name = "testcrt-3"
		crt4Name = "testcrt-4"
		ns1      = "testns-1"
		ns2      = "testns-2"
	)

	// Create Namespaces
	for _, ns := range []string{ns1, ns2} {
		_, err := kubeClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}

	crt1 := gen.Certificate(crt1Name,
		gen.SetCertificateNamespace(ns1),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Kind: "Issuer", Name: "test-issuer"}),
		gen.SetCertificateSecretName("crt1"),
		gen.SetCertificateCommonName("crt1"),
	)
	crt2 := gen.Certificate(crt2Name,
		gen.SetCertificateNamespace(ns1),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Kind: "Issuer", Name: "test-issuer"}),
		gen.SetCertificateSecretName("crt2"),
		gen.SetCertificateCommonName("crt2"),
		gen.AddCertificateLabels(map[string]string{
			"foo": "bar",
		}),
	)
	crt3 := gen.Certificate(crt3Name,
		gen.SetCertificateNamespace(ns2),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Kind: "Issuer", Name: "test-issuer"}),
		gen.SetCertificateSecretName("crt3"),
		gen.SetCertificateCommonName("crt3"),
		gen.AddCertificateLabels(map[string]string{
			"foo": "bar",
		}),
	)
	crt4 := gen.Certificate(crt4Name,
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Kind: "Issuer", Name: "test-issuer"}),
		gen.SetCertificateSecretName("crt4"),
		gen.SetCertificateCommonName("crt5"),
		gen.SetCertificateNamespace(ns2),
	)

	tests := map[string]struct {
		inputArgs          []string
		inputLabels        string
		inputNamespace     string
		inputAll           bool
		inputAllNamespaces bool

		crtsWithIssuing map[*cmapi.Certificate]bool
	}{
		"certificate name and namespace given": {
			inputArgs:      []string{crt1Name, crt2Name},
			inputNamespace: ns1,
			crtsWithIssuing: map[*cmapi.Certificate]bool{
				crt1: true,
				crt2: true,
				crt3: false,
				crt4: false,
			},
		},
		"--all and namespace given": {
			inputAll:       true,
			inputNamespace: ns2,

			crtsWithIssuing: map[*cmapi.Certificate]bool{
				crt1: false,
				crt2: false,
				crt3: true,
				crt4: true,
			},
		},
		"--all and --all-namespaces given": {
			inputAll:           true,
			inputAllNamespaces: true,

			crtsWithIssuing: map[*cmapi.Certificate]bool{
				crt1: true,
				crt2: true,
				crt3: true,
				crt4: true,
			},
		},
		"--all-namespaces and -l foo=bar given": {
			inputAllNamespaces: true,
			inputLabels:        "foo=bar",

			crtsWithIssuing: map[*cmapi.Certificate]bool{
				crt1: false,
				crt2: true,
				crt3: true,
				crt4: false,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create Certificates
			for _, crt := range []*cmapi.Certificate{crt1, crt2, crt3, crt4} {
				_, err := cmCl.CertmanagerV1().Certificates(crt.Namespace).Create(ctx, crt, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}

			// Run ctl renew command with input options
			streams, _, _, _ := genericclioptions.NewTestIOStreams()

			cmd := &renew.Options{
				LabelSelector: test.inputLabels,
				All:           test.inputAll,
				AllNamespaces: test.inputAllNamespaces,
				Factory: &factory.Factory{
					CMClient:   cmCl,
					RESTConfig: config,
					Namespace:  test.inputNamespace,
				},
				IOStreams: streams,
			}

			if err := cmd.Run(ctx, test.inputArgs); err != nil {
				t.Fatal(err)
			}

			// Check issuing condition against Certificates
			for crt, shouldIssue := range test.crtsWithIssuing {
				gotCrt, err := cmCl.CertmanagerV1().Certificates(crt.Namespace).Get(ctx, crt.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}

				hasCondition := true
				if cond := apiutil.GetCertificateCondition(gotCrt, cmapi.CertificateConditionIssuing); cond == nil || cond.Status != cmmeta.ConditionTrue {
					hasCondition = false
				}

				if shouldIssue != hasCondition {
					t.Errorf("%s/%s expected to have issuing condition=%t got=%t", crt.Namespace, crt.Name, shouldIssue, hasCondition)
				}
			}

			// Clean up Certificates
			for _, crt := range []*cmapi.Certificate{crt1, crt2, crt3, crt4} {
				err := cmCl.CertmanagerV1().Certificates(crt.Namespace).Delete(ctx, crt.Name, metav1.DeleteOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
