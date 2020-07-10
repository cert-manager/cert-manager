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
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	statuscertcmd "github.com/jetstack/cert-manager/cmd/ctl/pkg/status/certificate"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/test/integration/framework"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestCtlStatusCert(t *testing.T) {
	config, stopFn := framework.RunControlPlane(t)
	defer stopFn()

	ctx, cancel := context.WithTimeout(context.TODO(), time.Second*20)
	defer cancel()

	// Build clients
	_, _, cmCl, _ := framework.NewClients(t, config)

	var (
		crt1Name  = "testcrt-1"
		crt2Name  = "testcrt-2"
		ns1       = "testns-1"
		reqName   = "testreq-1"
		revision1 = 1
		revision2 = 2

		crtReadyAndUpToDateCond = cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue, Message: "Certificate is up to date and has not expired"}
		crtIssuingCond = cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue, Message: "Issuance of a new Certificate is in Progress"}

		reqNotReadyCond = cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: "Pending", Message: "Waiting on certificate issuance from order default/example-order: \"pending\""}
	)

	certIsValidTime, err := time.Parse(time.RFC3339, "2020-09-16T09:26:18Z")
	if err != nil {
		t.Fatal(err)
	}

	req1 := gen.CertificateRequest(reqName,
		gen.SetCertificateRequestNamespace(ns1),
		gen.SetCertificateRequestAnnotations(map[string]string{cmapi.CertificateRequestRevisionAnnotationKey: fmt.Sprintf("%d", revision2)}),
		gen.SetCertificateRequestCSR([]byte("dummyCSR")))

	tests := map[string]struct {
		certificate       *cmapi.Certificate
		certificateStatus *cmapi.CertificateStatus
		inputArgs         []string
		inputNamespace    string
		req               *cmapi.CertificateRequest
		reqStatus         *cmapi.CertificateRequestStatus

		expErr    bool
		expOutput string
	}{
		"certificate issued and up-to-date": {
			certificate: gen.Certificate(crt1Name,
				gen.SetCertificateNamespace(ns1),
				gen.SetCertificateDNSNames("www.example.com"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "letsencrypt-prod", Kind: "ClusterIssuer"}),
				gen.SetCertificateSecretName("example-tls")),
			certificateStatus: &cmapi.CertificateStatus{Conditions: []cmapi.CertificateCondition{crtReadyAndUpToDateCond},
				NotAfter: &metav1.Time{Time: certIsValidTime}, Revision: &revision1},
			inputArgs:      []string{crt1Name},
			inputNamespace: ns1,
			expErr:         false,
			expOutput: `Name: testcrt-1
Namespace: testns-1
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
DNS Names:
- www.example.com
Issuer:
  Name: letsencrypt-prod
  Kind: ClusterIssuer
Secret Name: example-tls
Not Before: <none>
Not After: 2020-09-16T09:26:18Z
Renewal Time: <none>
No CertificateRequest found for this Certificate`,
		},
		"certificate issued and renewal in progress": {
			certificate: gen.Certificate(crt2Name,
				gen.SetCertificateNamespace(ns1),
				gen.SetCertificateDNSNames("www.example.com"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "letsencrypt-prod", Kind: "ClusterIssuer"}),
				gen.SetCertificateSecretName("example-tls")),
			certificateStatus: &cmapi.CertificateStatus{Conditions: []cmapi.CertificateCondition{crtReadyAndUpToDateCond, crtIssuingCond},
				NotAfter: &metav1.Time{Time: certIsValidTime}, Revision: &revision1},
			inputArgs:      []string{crt2Name},
			inputNamespace: ns1,
			req:            req1,
			reqStatus:      &cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{reqNotReadyCond}},
			expErr:         false,
			expOutput: `Name: testcrt-2
Namespace: testns-1
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
  Issuing: True, Reason: , Message: Issuance of a new Certificate is in Progress
DNS Names:
- www.example.com
Issuer:
  Name: letsencrypt-prod
  Kind: ClusterIssuer
Secret Name: example-tls
Not Before: <none>
Not After: 2020-09-16T09:26:18Z
Renewal Time: <none>
CertificateRequest:
  Name: testreq-1
  Namespace: testns-1
  Conditions:
    Ready: False, Reason: Pending, Message: Waiting on certificate issuance from order default/example-order: "pending"`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create Certificate resource
			crt, err := cmCl.CertmanagerV1alpha2().Certificates(test.inputNamespace).Create(ctx, test.certificate, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			crt, err = setCertificateStatus(cmCl, crt, test.certificateStatus, ctx)
			if err != nil {
				t.Fatal(err)
			}

			if test.req != nil {
				err = createCROwnedByCrt(t, cmCl, ctx, crt, test.req, test.reqStatus)
				if err != nil {
					t.Fatal(err)
				}
			}

			// Options to run status command
			streams, _, outBuf, _ := genericclioptions.NewTestIOStreams()
			opts := &statuscertcmd.Options{
				CMClient:   cmCl,
				RESTConfig: config,
				IOStreams:  streams,
				Namespace:  test.inputNamespace,
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
				t.Errorf("got unexpected output, exp=\n%s\n\nbut got=\n%s",
					strings.TrimSpace(test.expOutput), strings.TrimSpace(outBuf.String()))
			}
		})
	}

}

func setCertificateStatus(cmCl versioned.Interface, crt *cmapi.Certificate,
	status *cmapi.CertificateStatus, ctx context.Context) (*cmapi.Certificate, error) {
	for _, cond := range status.Conditions {
		apiutil.SetCertificateCondition(crt, cond.Type, cond.Status, cond.Reason, cond.Message)
	}
	crt.Status.NotAfter = status.NotAfter
	crt.Status.Revision = status.Revision
	crt, err := cmCl.CertmanagerV1alpha2().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	return crt, err
}

func createCROwnedByCrt(t *testing.T, cmCl versioned.Interface, ctx context.Context, crt *cmapi.Certificate,
	req *cmapi.CertificateRequest, reqStatus *cmapi.CertificateRequestStatus) error {
	req, err := cmCl.CertmanagerV1alpha2().CertificateRequests(crt.Namespace).Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	req.OwnerReferences = append(req.OwnerReferences, *metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate")))
	req, err = cmCl.CertmanagerV1alpha2().CertificateRequests(crt.Namespace).Update(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Errorf("Update Err: %v", err)
	}

	if reqStatus != nil {
		req.Status.Conditions = reqStatus.Conditions
	}
	req, err = cmCl.CertmanagerV1alpha2().CertificateRequests(crt.Namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		t.Errorf("Update Err: %v", err)
	}
	return nil
}
