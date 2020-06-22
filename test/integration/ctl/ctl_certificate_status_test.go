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
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/certificate/status"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/integration/framework"
	"github.com/jetstack/cert-manager/test/unit/gen"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"strings"
	"testing"
	"time"
)

func TestCtlCertStatus(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	// Build clients
	//kubeClient, _, cmCl, _ := framework.NewClients(t, config)
	_, _, cmCl, _ := framework.NewClients(t, config)

	const (
		issuedAndUpToDate = `Name: testcrt-1
Namespace: testns-1
Status: Certificate is issued and up to date
DNS Names:
- www.example.com
Issuer:
  Name: letsencrypt-prod
  Kind: ClusterIssuer
Secret Name: example-tls
Not After: 2020-09-16T09:26:18Z`)

	var (
		crt1Name = "testcrt-1"
		ns1      = "testns-1"
	)

	certIsValidTime, err := time.Parse(time.RFC3339, "2020-09-16T09:26:18Z")
	if err != nil {
		t.Fatal(err)
	}
	//certIsInvalidTime, err :=

	crt1 := gen.Certificate(crt1Name,
		gen.SetCertificateNamespace(ns1),
		gen.SetCertificateStatusCondition(cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady,
			Message: "Certificate is up to date and has not expired"}),
		gen.SetCertificateDNSNames("www.example.com"),
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "letsencrypt-prod", Kind: "ClusterIssuer"}),
		gen.SetCertificateSecretName("example-tls"),
		gen.SetCertificateNotAfter(metav1.Time{Time: certIsValidTime}),
	)

	tests := map[string]struct {
		certificate *cmapi.Certificate
		inputArgs []string
		inputNamespace string

		expErr bool
		expOutput string
	}{
		"certificate name and namespace given": {
			certificate: crt1,
			inputArgs:  []string{crt1Name},
			inputNamespace: ns1,
			expErr: false,
			expOutput: issuedAndUpToDate,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create Certificate resource
			_, err := cmCl.CertmanagerV1alpha2().Certificates(test.inputNamespace).Create(ctx, test.certificate, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}

			// Options to run status command
			streams, _, outBuf, _ := genericclioptions.NewTestIOStreams()
			opts := &status.Options {
				CMClient:         cmCl,
				RESTConfig:       config,
				IOStreams:        streams,
				Namespace: test.inputNamespace,
			}

			err = opts.Run(test.inputArgs)
			if err != nil {
				if !test.expErr {
					t.Errorf("got unexpected error when validating args and flags: %v", err)
				}
				t.Logf("got an error, which was expected, details: %v", err)
				return
			} else {
				// got no error
				if test.expErr {
					t.Errorf("expected but got no error validating args and flags")
				}
			}

			if strings.TrimSpace(test.expOutput) != strings.TrimSpace(outBuf.String()) {
				t.Errorf("got unexpected output, exp=\n%s\nbut got=\n%s",
					strings.TrimSpace(test.expOutput), strings.TrimSpace(outBuf.String()))
			}
		})
	}

}