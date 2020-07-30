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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sergi/go-diff/diffmatchpatch"
	v1 "k8s.io/api/core/v1"
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
	kubernetesCl, _, cmCl, _ := framework.NewClients(t, config)

	var (
		crt1Name  = "testcrt-1"
		crt2Name  = "testcrt-2"
		crt3Name  = "testcrt-3"
		crt4Name  = "testcrt-4"
		ns1       = "testns-1"
		req1Name  = "testreq-1"
		req2Name  = "testreq-2"
		req3Name  = "testreq-3"
		revision1 = 1
		revision2 = 2

		crtReadyAndUpToDateCond = cmapi.CertificateCondition{Type: cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue, Message: "Certificate is up to date and has not expired"}
		crtIssuingCond = cmapi.CertificateCondition{Type: cmapi.CertificateConditionIssuing,
			Status: cmmeta.ConditionTrue, Message: "Issuance of a new Certificate is in Progress"}

		reqNotReadyCond = cmapi.CertificateRequestCondition{Type: cmapi.CertificateRequestConditionReady, Status: cmmeta.ConditionFalse, Reason: "Pending", Message: "Waiting on certificate issuance from order default/example-order: \"pending\""}

		tlsCrt = []byte(`-----BEGIN CERTIFICATE-----
MIICyTCCAbGgAwIBAgIRAOL4jtyULBSEYyGdqQn9YzowDQYJKoZIhvcNAQELBQAw
DzENMAsGA1UEAxMEdGVzdDAeFw0yMDA3MzAxNjExNDNaFw0yMDEwMjgxNjExNDNa
MA8xDTALBgNVBAMTBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDdfNmjh5ag7f6U1hj1OAx/dEN9kQzPsSlBMXGb/Ho4k5iegrFd6w8JkYdCthFv
lfg3bIhw5tCKaw1o57HnWKBKKGt7XpeIu1mEcv8pveMIPO7TZ4+oElgX880NfJmL
DkjEcctEo/+FurudO1aEbNfbNWpzudYKj7gGtYshBytqaYt4/APqWARJBFCYVVys
wexZ0fLi5cBD8H1bQ1Ec3OCr5Mrq9thAGkj+rVlgYR0AZVGa9+SCOj27t6YCmyzR
AJSEQ35v58Zfxp5tNyYd6wcAswJ9YipnUXvwahF95PNlRmMhp3Eo15m9FxehcVXU
BOfxykMwZN7onMhuHiiwiB+NAgMBAAGjIDAeMA4GA1UdDwEB/wQEAwIFoDAMBgNV
HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQALrnldWjTBTvV5WKapUHUG0rhA
vp2Cf+5FsPw8vKScXp4L+wKGdPOjhHz6NOiw5wu8A0HxlVUFawRpagkjFkeTL78O
9ghBHLiqn9xNPIKC6ID3WpnN5terwQxQeO/M54sVMslUWCcZm9Pu4Eb//2e6wEdu
eMmpfeISQmCsBC1CTmpxUjeUg5DEQ0X1TQykXq+bG2iso6RYPxZTFTHJFzXiDYEc
/X7H+bOmpo/dMrXapwfvp2gD+BEq96iVpf/DBzGYNs/657LAHJ4YtxtAZCa1CK9G
MA6koCR/K23HZfML8vT6lcHvQJp9XXaHRIe9NX/M/2f6VpfO7JjKWLou5k5a
-----END CERTIFICATE-----`)
	)
	certIsValidTime, err := time.Parse(time.RFC3339, "2020-09-16T09:26:18Z")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		certificate       *cmapi.Certificate
		certificateStatus *cmapi.CertificateStatus
		inputArgs         []string
		inputNamespace    string
		req               *cmapi.CertificateRequest
		reqStatus         *cmapi.CertificateRequestStatus
		// At most one of issuer and clusterIssuer is not nil
		issuer        *cmapi.Issuer
		clusterIssuer *cmapi.ClusterIssuer
		secret        *v1.Secret

		expErr    bool
		expOutput string
	}{
		"certificate issued and up-to-date with clusterIssuer": {
			certificate: gen.Certificate(crt1Name,
				gen.SetCertificateNamespace(ns1),
				gen.SetCertificateDNSNames("www.example.com"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "letsencrypt-prod", Kind: "ClusterIssuer"}),
				gen.SetCertificateSecretName("example-tls")),
			certificateStatus: &cmapi.CertificateStatus{Conditions: []cmapi.CertificateCondition{crtReadyAndUpToDateCond},
				NotAfter: &metav1.Time{Time: certIsValidTime}, Revision: &revision1},
			inputArgs:      []string{crt1Name},
			inputNamespace: ns1,
			clusterIssuer:  gen.ClusterIssuer("letsencrypt-prod"),
			expErr:         false,
			expOutput: `Name: testcrt-1
Namespace: testns-1
Created at: ([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
DNS Names:
- www.example.com
Events:  <none>
Issuer:
  Name: letsencrypt-prod
  Kind: ClusterIssuer
  Conditions:
    No Conditions set
error when finding secret "example-tls": secrets "example-tls" not found
Not Before: <none>
Not After: 2020-09-16T09:26:18Z
Renewal Time: <none>
No CertificateRequest found for this Certificate`,
		},
		"certificate issued and renewal in progress with Issuer": {
			certificate: gen.Certificate(crt2Name,
				gen.SetCertificateNamespace(ns1),
				gen.SetCertificateDNSNames("www.example.com"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "letsencrypt-prod", Kind: "Issuer"}),
				gen.SetCertificateSecretName("existing-tls-secret")),
			certificateStatus: &cmapi.CertificateStatus{Conditions: []cmapi.CertificateCondition{crtReadyAndUpToDateCond, crtIssuingCond},
				NotAfter: &metav1.Time{Time: certIsValidTime}, Revision: &revision1},
			inputArgs:      []string{crt2Name},
			inputNamespace: ns1,
			req: gen.CertificateRequest(req1Name,
				gen.SetCertificateRequestNamespace(ns1),
				gen.SetCertificateRequestAnnotations(map[string]string{cmapi.CertificateRequestRevisionAnnotationKey: fmt.Sprintf("%d", revision2)}),
				gen.SetCertificateRequestCSR([]byte("dummyCSR"))),
			reqStatus: &cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{reqNotReadyCond}},
			issuer: gen.Issuer("letsencrypt-prod",
				gen.SetIssuerNamespace(ns1)),
			secret: gen.Secret("existing-tls-secret",
				gen.SetSecretNamespace(ns1),
				gen.SetSecretData(map[string][]byte{"tls.crt": tlsCrt})),
			expErr: false,
			expOutput: `Name: testcrt-2
Namespace: testns-1
Created at: ([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
  Issuing: True, Reason: , Message: Issuance of a new Certificate is in Progress
DNS Names:
- www.example.com
Events:  <none>
Issuer:
  Name: letsencrypt-prod
  Kind: Issuer
  Conditions:
    No Conditions set
Secret:
  Name: existing-tls-secret
  Issuer Country: 
  Issuer Organisation: 
  Issuer Common Name: test
  Key Usage: Digital Signature, Key Encipherment
  Extended Key Usages: 
  Public Key Algorithm: RSA
  Signature Algorithm: SHA256-RSA
  Subject Key ID: 
  Authority Key ID: 
  Serial Number: e2f88edc942c148463219da909fd633a
Not Before: <none>
Not After: 2020-09-16T09:26:18Z
Renewal Time: <none>
CertificateRequest:
  Name: testreq-1
  Namespace: testns-1
  Conditions:
    Ready: False, Reason: Pending, Message: Waiting on certificate issuance from order default/example-order: "pending"
  Events:  <none>`,
		},
		"certificate issued and renewal in progress without Issuer": {
			certificate: gen.Certificate(crt3Name,
				gen.SetCertificateNamespace(ns1),
				gen.SetCertificateDNSNames("www.example.com"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "non-existing-issuer", Kind: "Issuer"}),
				gen.SetCertificateSecretName("example-tls")),
			certificateStatus: &cmapi.CertificateStatus{Conditions: []cmapi.CertificateCondition{crtReadyAndUpToDateCond, crtIssuingCond},
				NotAfter: &metav1.Time{Time: certIsValidTime}, Revision: &revision1},
			inputArgs:      []string{crt3Name},
			inputNamespace: ns1,
			req: gen.CertificateRequest(req2Name,
				gen.SetCertificateRequestNamespace(ns1),
				gen.SetCertificateRequestAnnotations(map[string]string{cmapi.CertificateRequestRevisionAnnotationKey: fmt.Sprintf("%d", revision2)}),
				gen.SetCertificateRequestCSR([]byte("dummyCSR"))),
			reqStatus: &cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{reqNotReadyCond}},
			issuer:    nil,
			expErr:    false,
			expOutput: `Name: testcrt-3
Namespace: testns-1
Created at: ([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
  Issuing: True, Reason: , Message: Issuance of a new Certificate is in Progress
DNS Names:
- www.example.com
Events:  <none>
error when getting Issuer: issuers.cert-manager.io "non-existing-issuer" not found
error when finding secret "example-tls": secrets "example-tls" not found
Not Before: <none>
Not After: 2020-09-16T09:26:18Z
Renewal Time: <none>
CertificateRequest:
  Name: testreq-2
  Namespace: testns-1
  Conditions:
    Ready: False, Reason: Pending, Message: Waiting on certificate issuance from order default/example-order: "pending"
  Events:  <none>`,
		},
		"certificate issued and renewal in progress without ClusterIssuer": {
			certificate: gen.Certificate(crt4Name,
				gen.SetCertificateNamespace(ns1),
				gen.SetCertificateDNSNames("www.example.com"),
				gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "non-existing-clusterissuer", Kind: "ClusterIssuer"}),
				gen.SetCertificateSecretName("example-tls")),
			certificateStatus: &cmapi.CertificateStatus{Conditions: []cmapi.CertificateCondition{crtReadyAndUpToDateCond, crtIssuingCond},
				NotAfter: &metav1.Time{Time: certIsValidTime}, Revision: &revision1},
			inputArgs:      []string{crt4Name},
			inputNamespace: ns1,
			req: gen.CertificateRequest(req3Name,
				gen.SetCertificateRequestNamespace(ns1),
				gen.SetCertificateRequestAnnotations(map[string]string{cmapi.CertificateRequestRevisionAnnotationKey: fmt.Sprintf("%d", revision2)}),
				gen.SetCertificateRequestCSR([]byte("dummyCSR"))),
			reqStatus: &cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{reqNotReadyCond}},
			issuer:    nil,
			expErr:    false,
			expOutput: `Name: testcrt-4
Namespace: testns-1
Created at: ([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
  Issuing: True, Reason: , Message: Issuance of a new Certificate is in Progress
DNS Names:
- www.example.com
Events:  <none>
error when getting ClusterIssuer: clusterissuers.cert-manager.io "non-existing-clusterissuer" not found
error when finding secret "example-tls": secrets "example-tls" not found
Not Before: <none>
Not After: 2020-09-16T09:26:18Z
Renewal Time: <none>
CertificateRequest:
  Name: testreq-3
  Namespace: testns-1
  Conditions:
    Ready: False, Reason: Pending, Message: Waiting on certificate issuance from order default/example-order: "pending"
  Events:  <none>`,
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

			if test.issuer != nil {
				_, err := cmCl.CertmanagerV1alpha2().Issuers(crt.Namespace).Create(ctx, test.issuer, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}
			if test.clusterIssuer != nil {
				_, err := cmCl.CertmanagerV1alpha2().ClusterIssuers().Create(ctx, test.clusterIssuer, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}

			if test.secret != nil {
				_, err = kubernetesCl.CoreV1().Secrets(test.inputNamespace).Create(ctx, test.secret, metav1.CreateOptions{})
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

			match, err := regexp.MatchString(strings.TrimSpace(test.expOutput), strings.TrimSpace(outBuf.String()))
			if err != nil {
				t.Error(err)
			}
			if !match {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(strings.TrimSpace(test.expOutput), strings.TrimSpace(outBuf.String()), false)
				t.Errorf("got unexpected ouput, diff (ignoring the regex for creation time): %s\n", dmp.DiffPrettyText(diffs))
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
