/*
Copyright 2020 The Jetstack cert-manager contributors.

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
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/create"
	"github.com/jetstack/cert-manager/test/integration/framework"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"testing"
	"time"
)

// TestCtlCreateCR tests the renewal logic of the ctl CLI command against the
// cert-manager Issuing controller.
func TestCtlCreateCR(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	// Build clients
	kubeClient, _, cmCl, _ := framework.NewClients(t, config)

	var (
		cr1Name = "testcr-1"
		cr2Name = "testcr-2"
		cr3Name = "testcr-3"
		cr4Name = "testcr-4"
		ns1     = "testns-1"
		ns2     = "testns-2"
	)

	// Create Namespaces
	for _, ns := range []string{ns1, ns2} {
		_, err := kubeClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}
	// TODO: what bout filepath
	tests := map[string]struct {
		inputFile      string
		inputArgs      []string
		inputNamespace string

		expErr       bool
		expNamespace string
		expName      string
	}{
		"v1alpha2 Certificate given": {
			inputFile:      "./testdata/create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{cr1Name},
			inputNamespace: ns1,
			expErr:         false,
			expNamespace:   ns1,
			expName:        cr1Name,
		},
		"v1alpha3 Certificate given": {
			inputFile:      "./testdata/create_cr_v1alpha3_cert_with_ns1.yaml",
			inputArgs:      []string{cr2Name},
			inputNamespace: ns1,
			expErr:         false,
			expNamespace:   ns1,
			expName:        cr2Name,
		},
		"conflicting namespaces defined in flag and file": {
			inputFile:      "./testdata/create_cr_cert_with_ns1.yaml",
			inputArgs:      []string{cr3Name},
			inputNamespace: ns2,
			expErr:         true,
			expNamespace:   "",
			expName:        "",
		},
		"file passed in defines resource other than certificate": {
			inputFile:      "./testdata/create_cr_issuer.yaml",
			inputArgs:      []string{cr4Name},
			inputNamespace: ns1,
			expErr:         true,
			expNamespace:   "",
			expName:        "",
		},
	}

	for name, test := range tests {
		// Run ctl create cr command with input options
		t.Run(name, func(t *testing.T) {
			streams, _, _, _ := genericclioptions.NewTestIOStreams()

			// Options to run create CR command
			opts := &create.Options{
				CMClient:         cmCl,
				RESTConfig:       config,
				IOStreams:        streams,
				CmdNamespace:     test.inputNamespace,
				EnforceNamespace: test.inputNamespace != "",
			}

			opts.Filenames = []string{test.inputFile}

			err := opts.Run(test.inputArgs)

			if err != nil {
				if !test.expErr {
					t.Errorf("got unexpected error when trying to create CR: %v", err)
				} else {
					t.Logf("got an error, which was expected, details: %v", err)
					return
				}
			} else {
				// got no error
				if test.expErr {
					t.Errorf("expected but got no error when to creating CR")
				}
			}

			// Finished creating CR, check if everything is expected
			crName := test.inputArgs[0]
			gotCr, err := cmCl.CertmanagerV1alpha2().CertificateRequests(test.inputNamespace).Get(ctx, crName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if gotCr.Namespace != test.expNamespace {
				t.Errorf("CR created in unexpected Namespace")
			}

			if gotCr.Name != test.expName {
				t.Errorf("CR created has unexpected Name")
			}

			// Clean up CertificateRequest
			// Everything is expected, so clean up with what is expected
			err = cmCl.CertmanagerV1alpha2().CertificateRequests(test.expNamespace).Delete(ctx, test.expName, metav1.DeleteOptions{})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
