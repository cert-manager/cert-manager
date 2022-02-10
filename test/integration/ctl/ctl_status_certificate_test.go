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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sergi/go-diff/diffmatchpatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/reference"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	statuscertcmd "github.com/cert-manager/cert-manager/cmd/ctl/pkg/status/certificate"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/cert-manager/pkg/ctl"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/integration/framework"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func generateCSR(t *testing.T) []byte {
	skRSA, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	asn1Subj, _ := asn1.Marshal(pkix.Name{
		CommonName: "test",
	}.ToRDNSequence())
	template := x509.CertificateRequest{
		RawSubject: asn1Subj,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, skRSA)
	if err != nil {
		t.Fatal(err)
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return csr
}

func TestCtlStatusCert(t *testing.T) {
	testCSR := generateCSR(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

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

	// Create Namespace
	_, err = kubernetesCl.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns1}}, metav1.CreateOptions{})
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
		secret        *corev1.Secret
		order         *cmacme.Order
		challenges    []*cmacme.Challenge
		crtEvents     *corev1.EventList
		issuerEvents  *corev1.EventList
		secretEvents  *corev1.EventList
		reqEvents     *corev1.EventList

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
			crtEvents: &corev1.EventList{
				Items: []corev1.Event{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "crtEvent",
						Namespace: ns1,
					},
					Type:    "type",
					Reason:  "reason",
					Message: "message",
				}},
			},
			inputArgs:      []string{crt1Name},
			inputNamespace: ns1,
			clusterIssuer:  gen.ClusterIssuer("letsencrypt-prod", gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{})),
			expErr:         false,
			expOutput: `^Name: testcrt-1
Namespace: testns-1
Created at: .*
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
DNS Names:
- www.example.com
Events:
  Type  Reason  Age        From  Message
  ----  ------  ----       ----  -------
  type  reason  <unknown>        message
Issuer:
  Name: letsencrypt-prod
  Kind: ClusterIssuer
  Conditions:
    No Conditions set
  Events:  <none>
error when finding Secret "example-tls": secrets "example-tls" not found
Not Before: <none>
Not After: .*
Renewal Time: <none>
No CertificateRequest found for this Certificate$`,
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
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "letsencrypt-prod", Kind: "Issuer"}),
				gen.SetCertificateRequestCSR(testCSR)),
			reqStatus: &cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{reqNotReadyCond}},
			issuer: gen.Issuer("letsencrypt-prod",
				gen.SetIssuerNamespace(ns1),
				gen.SetIssuerACME(cmacme.ACMEIssuer{
					Server: "https://dummy.acme.local/",
					PrivateKey: cmmeta.SecretKeySelector{
						LocalObjectReference: cmmeta.LocalObjectReference{
							Name: "test",
						},
						Key: "test",
					},
				})),
			issuerEvents: &corev1.EventList{
				Items: []corev1.Event{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "issuerEvent",
					},
					Type:    "type",
					Reason:  "reason",
					Message: "message",
				}},
			},
			secret: gen.Secret("existing-tls-secret",
				gen.SetSecretNamespace(ns1),
				gen.SetSecretData(map[string][]byte{"tls.crt": tlsCrt})),
			secretEvents: &corev1.EventList{
				Items: []corev1.Event{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secretEvent",
						Namespace: ns1,
					},
					Type:    "type",
					Reason:  "reason",
					Message: "message",
				}},
			},
			order: gen.Order("example-order",
				gen.SetOrderNamespace(ns1),
				gen.SetOrderCsr(testCSR),
				gen.SetOrderIssuer(cmmeta.ObjectReference{Name: "letsencrypt-prod", Kind: "Issuer"}),
				gen.SetOrderDNSNames("www.example.com")),
			challenges: []*cmacme.Challenge{
				gen.Challenge("test-challenge1",
					gen.SetChallengeNamespace(ns1),
					gen.SetChallengeType(cmacme.ACMEChallengeTypeHTTP01),
					gen.SetChallengeToken("dummy-token1"),
					gen.SetChallengePresented(false),
					gen.SetChallengeProcessing(false),
				),
				gen.Challenge("test-challenge2",
					gen.SetChallengeNamespace(ns1),
					gen.SetChallengeType(cmacme.ACMEChallengeTypeDNS01),
					gen.SetChallengeToken("dummy-token2"),
					gen.SetChallengePresented(false),
					gen.SetChallengeProcessing(false),
				),
			},
			expErr: false,
			expOutput: `^Name: testcrt-2
Namespace: testns-1
Created at: .*
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
  Events:
    Type  Reason  Age        From  Message
    ----  ------  ----       ----  -------
    type  reason  <unknown>        message
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
  Events:
    Type  Reason  Age        From  Message
    ----  ------  ----       ----  -------
    type  reason  <unknown>        message
Not Before: <none>
Not After: .*
Renewal Time: <none>
CertificateRequest:
  Name: testreq-1
  Namespace: testns-1
  Conditions:
    Ready: False, Reason: Pending, Message: Waiting on certificate issuance from order default/example-order: "pending"
  Events:  <none>
Order:
  Name: example-order
  State: , Reason: 
  No Authorizations for this Order
Challenges:
- Name: test-challenge1, Type: HTTP-01, Token: dummy-token1, Key: , State: , Reason: , Processing: false, Presented: false
- Name: test-challenge2, Type: DNS-01, Token: dummy-token2, Key: , State: , Reason: , Processing: false, Presented: false$`,
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
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "non-existing-issuer", Kind: "Issuer"}),
				gen.SetCertificateRequestCSR(testCSR)),
			reqStatus: &cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{reqNotReadyCond}},
			reqEvents: &corev1.EventList{
				Items: []corev1.Event{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "reqEvent",
						Namespace: ns1,
					},
					Type:    "type",
					Reason:  "reason",
					Message: "message",
				}},
			},
			issuer: nil,
			expErr: false,
			expOutput: `^Name: testcrt-3
Namespace: testns-1
Created at: .*
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
  Issuing: True, Reason: , Message: Issuance of a new Certificate is in Progress
DNS Names:
- www.example.com
Events:  <none>
error when getting Issuer: issuers.cert-manager.io "non-existing-issuer" not found
error when finding Secret "example-tls": secrets "example-tls" not found
Not Before: <none>
Not After: .*
Renewal Time: <none>
CertificateRequest:
  Name: testreq-2
  Namespace: testns-1
  Conditions:
    Ready: False, Reason: Pending, Message: Waiting on certificate issuance from order default/example-order: "pending"
  Events:
    Type  Reason  Age        From  Message
    ----  ------  ----       ----  -------
    type  reason  <unknown>        message$`,
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
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "non-existing-clusterissuer", Kind: "ClusterIssuer"}),
				gen.SetCertificateRequestAnnotations(map[string]string{cmapi.CertificateRequestRevisionAnnotationKey: fmt.Sprintf("%d", revision2)}),
				gen.SetCertificateRequestCSR(testCSR)),
			reqStatus: &cmapi.CertificateRequestStatus{Conditions: []cmapi.CertificateRequestCondition{reqNotReadyCond}},
			issuer:    nil,
			expErr:    false,
			expOutput: `^Name: testcrt-4
Namespace: testns-1
Created at: .*
Conditions:
  Ready: True, Reason: , Message: Certificate is up to date and has not expired
  Issuing: True, Reason: , Message: Issuance of a new Certificate is in Progress
DNS Names:
- www.example.com
Events:  <none>
error when getting ClusterIssuer: clusterissuers.cert-manager.io "non-existing-clusterissuer" not found
error when finding Secret "example-tls": secrets "example-tls" not found
Not Before: <none>
Not After: .*
Renewal Time: <none>
CertificateRequest:
  Name: testreq-3
  Namespace: testns-1
  Conditions:
    Ready: False, Reason: Pending, Message: Waiting on certificate issuance from order default/example-order: "pending"
  Events:  <none>$`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Create Certificate resource
			crt, err := cmCl.CertmanagerV1().Certificates(test.inputNamespace).Create(ctx, test.certificate, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			crt, err = setCertificateStatus(cmCl, crt, test.certificateStatus, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if test.crtEvents != nil {
				crtRef, err := reference.GetReference(ctl.Scheme, crt)
				if err != nil {
					t.Fatalf("error when getting ObjectReference: %v", err)
				}
				err = createEventsOwnedByRef(kubernetesCl, ctx, test.crtEvents, crtRef, crt.Namespace)
				if err != nil {
					t.Fatal(err)
				}
			}

			// Set up related resources
			if test.req != nil {
				req, err := createCROwnedByCrt(cmCl, ctx, crt, test.req, test.reqStatus)
				if err != nil {
					t.Fatal(err)
				}
				if test.reqEvents != nil {
					reqRef, err := reference.GetReference(ctl.Scheme, req)
					if err != nil {
						t.Fatalf("error when getting ObjectReference: %v", err)
					}
					err = createEventsOwnedByRef(kubernetesCl, ctx, test.reqEvents, reqRef, req.Namespace)
					if err != nil {
						t.Fatal(err)
					}
				}
			}

			if test.issuer != nil {
				issuer, err := cmCl.CertmanagerV1().Issuers(crt.Namespace).Create(ctx, test.issuer, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if test.issuerEvents != nil {
					issuerRef, err := reference.GetReference(ctl.Scheme, issuer)
					if err != nil {
						t.Fatalf("error when getting ObjectReference: %v", err)
					}
					err = createEventsOwnedByRef(kubernetesCl, ctx, test.issuerEvents, issuerRef, issuer.Namespace)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if test.clusterIssuer != nil {
				clusterIssuer, err := cmCl.CertmanagerV1().ClusterIssuers().Create(ctx, test.clusterIssuer, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if test.issuerEvents != nil {
					issuerRef, err := reference.GetReference(ctl.Scheme, clusterIssuer)
					if err != nil {
						t.Fatalf("error when getting ObjectReference: %v", err)
					}
					err = createEventsOwnedByRef(kubernetesCl, ctx, test.issuerEvents, issuerRef, clusterIssuer.Namespace)
					if err != nil {
						t.Fatal(err)
					}
				}
			}

			if test.secret != nil {
				secret, err := kubernetesCl.CoreV1().Secrets(test.inputNamespace).Create(ctx, test.secret, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if test.secretEvents != nil {
					secretRef, err := reference.GetReference(ctl.Scheme, secret)
					if err != nil {
						t.Fatalf("error when getting ObjectReference: %v", err)
					}
					err = createEventsOwnedByRef(kubernetesCl, ctx, test.secretEvents, secretRef, secret.Namespace)
					if err != nil {
						t.Fatal(err)
					}
				}
			}

			if test.order != nil {
				createdReq, err := cmCl.CertmanagerV1().CertificateRequests(test.req.Namespace).Get(ctx, test.req.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				err = createOrderOwnedByCR(cmCl, ctx, createdReq, test.order)
				if err != nil {
					t.Fatal(err)
				}
			}

			if len(test.challenges) > 0 {
				createdOrder, err := cmCl.AcmeV1().Orders(test.req.Namespace).Get(ctx, test.order.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				err = createChallengesOwnedByOrder(cmCl, ctx, createdOrder, test.challenges)
				if err != nil {
					t.Fatal(err)
				}
			}

			// Options to run status command
			streams, _, outBuf, _ := genericclioptions.NewTestIOStreams()
			opts := &statuscertcmd.Options{
				Factory: &factory.Factory{
					CMClient:   cmCl,
					RESTConfig: config,
					Namespace:  test.inputNamespace,
				},
				IOStreams: streams,
			}

			err = opts.Run(ctx, test.inputArgs)
			if err != nil {
				if !test.expErr {
					t.Errorf("got unexpected error: %v", err)
				} else {
					t.Logf("got an error, which was expected, details: %v", err)
				}
				return
			} else if test.expErr {
				// expected error but error is nil
				t.Error("got no error but expected one")
				return
			}

			expectedOutput := strings.TrimSpace(test.expOutput)
			commandOutput := strings.TrimSpace(outBuf.String())

			match, err := regexp.MatchString(expectedOutput, commandOutput)
			if err != nil {
				t.Errorf("failed to match regex for output: %s", err)
			}

			if !match {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(expectedOutput, commandOutput, false)
				t.Errorf("got unexpected output, diff (ignoring line anchors ^ and $ and regex for creation time):\n%s\n\n expected: \n%s\n\n got: \n%s", dmp.DiffPrettyText(diffs), test.expOutput, outBuf.String())
			}

			err = validateOutputTimes(commandOutput, certIsValidTime)
			if err != nil {
				t.Errorf("couldn't validate times in output: %s", err)
			}
		})
	}

}

func setCertificateStatus(cmCl versioned.Interface, crt *cmapi.Certificate,
	status *cmapi.CertificateStatus, ctx context.Context) (*cmapi.Certificate, error) {
	for _, cond := range status.Conditions {
		apiutil.SetCertificateCondition(crt, crt.Generation, cond.Type, cond.Status, cond.Reason, cond.Message)
	}
	crt.Status.NotAfter = status.NotAfter
	crt.Status.Revision = status.Revision
	crt, err := cmCl.CertmanagerV1().Certificates(crt.Namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	return crt, err
}

func createCROwnedByCrt(cmCl versioned.Interface, ctx context.Context, crt *cmapi.Certificate,
	req *cmapi.CertificateRequest, reqStatus *cmapi.CertificateRequestStatus) (*cmapi.CertificateRequest, error) {

	req, err := cmCl.CertmanagerV1().CertificateRequests(crt.Namespace).Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	req.OwnerReferences = append(req.OwnerReferences, *metav1.NewControllerRef(crt, cmapi.SchemeGroupVersion.WithKind("Certificate")))
	req, err = cmCl.CertmanagerV1().CertificateRequests(crt.Namespace).Update(ctx, req, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("Update Err: %v", err)
	}

	if reqStatus != nil {
		req.Status.Conditions = reqStatus.Conditions
		req, err = cmCl.CertmanagerV1().CertificateRequests(crt.Namespace).UpdateStatus(ctx, req, metav1.UpdateOptions{})
		if err != nil {
			return nil, fmt.Errorf("Update Err: %v", err)
		}
	}
	return req, nil
}

func createOrderOwnedByCR(cmCl versioned.Interface, ctx context.Context,
	req *cmapi.CertificateRequest, order *cmacme.Order) error {

	order, err := cmCl.AcmeV1().Orders(req.Namespace).Create(ctx, order, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	order.OwnerReferences = append(order.OwnerReferences, *metav1.NewControllerRef(req, cmapi.SchemeGroupVersion.WithKind("CertificateRequest")))
	_, err = cmCl.AcmeV1().Orders(req.Namespace).Update(ctx, order, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("Update Err: %v", err)
	}

	return nil
}

func createChallengesOwnedByOrder(cmCl versioned.Interface, ctx context.Context,
	order *cmacme.Order, challenges []*cmacme.Challenge) error {

	for _, c := range challenges {
		challenge, err := cmCl.AcmeV1().Challenges(order.Namespace).Create(ctx, c, metav1.CreateOptions{})
		if err != nil {
			return err
		}

		challenge.OwnerReferences = append(challenge.OwnerReferences, *metav1.NewControllerRef(order, cmacme.SchemeGroupVersion.WithKind("Order")))
		_, err = cmCl.AcmeV1().Challenges(order.Namespace).Update(ctx, challenge, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("Update Err: %v", err)
		}
	}

	return nil
}

func createEventsOwnedByRef(kubernetesCl kubernetes.Interface, ctx context.Context,
	eventList *corev1.EventList, objRef *corev1.ObjectReference, ns string) error {
	for _, event := range eventList.Items {
		event.InvolvedObject = *objRef
		_, err := kubernetesCl.CoreV1().Events(ns).Create(ctx, &event, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf(err.Error())
		}
	}
	return nil
}

func validateOutputTimes(output string, expectedNotAfter time.Time) error {
	for _, line := range strings.Split(output, "\n") {
		rawParts := strings.Split(strings.TrimSpace(line), ":")

		if len(rawParts) == 1 {
			continue
		}

		partType := strings.ToLower(rawParts[0])
		rest := strings.TrimSpace(strings.Join(rawParts[1:], ":"))

		if partType == "created at" {
			_, err := time.Parse(time.RFC3339, rest)
			if err != nil {
				return fmt.Errorf("couldn't parse 'created at' as an RFC3339 timestamp: %s", err)
			}
		} else if partType == "not after" {
			notAfter, err := time.Parse(time.RFC3339, rest)
			if err != nil {
				return fmt.Errorf("couldn't parse 'not after' as an RFC3339 timestamp: %s", err)
			}

			if !notAfter.Equal(expectedNotAfter) {
				return fmt.Errorf("got unexpected 'not after' (note that time zone differences could be a red herring) - wanted %q but got %q", expectedNotAfter.Format(time.RFC3339), notAfter.Format(time.RFC3339))
			}
		}
	}

	return nil
}
