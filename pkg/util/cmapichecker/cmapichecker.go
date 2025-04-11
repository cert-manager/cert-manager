/*
Copyright 2021 The cert-manager Authors.

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

package cmapichecker

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var (
	ErrCertManagerCRDsNotFound   = fmt.Errorf("the cert-manager CRDs are not yet installed on the Kubernetes API server")
	ErrWebhookServiceFailure     = fmt.Errorf("the cert-manager webhook service is not created yet")
	ErrWebhookDeploymentFailure  = fmt.Errorf("the cert-manager webhook deployment is not ready yet")
	ErrWebhookCertificateFailure = fmt.Errorf("the cert-manager webhook CA bundle is not injected yet")
	ErrMutationWebhookMissing    = fmt.Errorf("the cert-manager mutation webhook did not mutate the dry-run CertificateRequest object")
	ErrValidatingWebhookMissing  = fmt.Errorf("the cert-manager validating webhook did not validate the dry-run CertificateRequest object")
	ErrMutationWebhookIncorrect  = fmt.Errorf("the cert-manager validating webhook failed because the dry-run CertificateRequest object was mutated incorrectly")

	ErrFailedToCheckAPI = fmt.Errorf("failed to check the cert-manager API")
)

var (
	regexErrCertManagerCRDsNotFound1  = regexp.MustCompile(`the server could not find the requested resource`)
	regexErrCertManagerCRDsNotFound2  = regexp.MustCompile(`failed to find API group "cert-manager\.io"`)
	regexErrCertManagerCRDsNotFound3  = regexp.MustCompile(`no resources found for group "cert-manager\.io/v1"`)
	regexErrCertManagerCRDsNotFound4  = regexp.MustCompile(`no matches for kind "CertificateRequest" in group "cert-manager\.io"`)
	regexErrCertManagerCRDsNotFound5  = regexp.MustCompile(`no matches for kind "CertificateRequest" in version "cert-manager\.io/v1"`)
	regexErrWebhookServiceFailure     = regexp.MustCompile(`Post "(.*)": service "(.*)-webhook" not found`)
	regexErrWebhookDeploymentFailure  = regexp.MustCompile(`Post "(.*)": (.*): connect: connection refused`)
	regexErrWebhookCertificateFailure = regexp.MustCompile(`Post "(.*)": x509: certificate signed by unknown authority`)
	regexErrCertmanagerDeniedRequest  = regexp.MustCompile(`admission webhook "webhook\.cert-manager\.io" denied the request: (.*)`)

	regexErrForbidden = regexp.MustCompile(`certificaterequests\.cert-manager\.io is forbidden`)
	regexErrDenied    = regexp.MustCompile(`admission webhook "(.*)" denied the request: (.*)`)
)

// Interface is used to check that the cert-manager CRDs have been installed and are usable.
type Interface interface {
	Check(context.Context) error
}

type cmapiChecker struct {
	client client.Client

	testValidCR   *cmapi.CertificateRequest
	testInvalidCR *cmapi.CertificateRequest
}

// New returns a cert-manager API checker
func New(restcfg *rest.Config, namespace string) (Interface, error) {
	httpClient, err := rest.HTTPClientFor(restcfg)
	if err != nil {
		return nil, fmt.Errorf("while creating HTTP client: %w", err)
	}

	return NewForConfigAndClient(restcfg, httpClient, namespace)
}

func NewForConfigAndClient(restcfg *rest.Config, httpClient *http.Client, namespace string) (Interface, error) {
	scheme := runtime.NewScheme()
	if err := cmapi.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("while configuring scheme: %w", err)
	}

	cl, err := client.New(restcfg, client.Options{
		HTTPClient: httpClient,
		Scheme:     scheme,
		DryRun:     ptr.To(true),
	})
	if err != nil {
		return nil, fmt.Errorf("while creating client: %w", err)
	}

	cl = client.NewNamespacedClient(cl, namespace)

	x509CertReq, err := pki.GenerateCSR(
		&cmapi.Certificate{
			Spec: cmapi.CertificateSpec{
				DNSNames: []string{"example.com"},
				PrivateKey: &cmapi.CertificatePrivateKey{
					Algorithm: "ECDSA",
					Size:      521,
				},
			},
		},
		pki.WithEncodeBasicConstraintsInRequest(true),
	)
	if err != nil {
		return nil, fmt.Errorf("while generating CSR: %w", err)
	}

	pk, err := pki.GenerateECPrivateKey(521)
	if err != nil {
		return nil, fmt.Errorf("while generating private key: %w", err)
	}

	csrDER, err := pki.EncodeCSR(x509CertReq, pk)
	if err != nil {
		return nil, fmt.Errorf("while encoding CSR: %w", err)
	}

	csrPEM := bytes.NewBuffer([]byte{})
	err = pem.Encode(csrPEM, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err != nil {
		return nil, fmt.Errorf("while encoding CSR to PEM: %w", err)
	}

	return &cmapiChecker{
		client: cl,
		testValidCR: &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cmapichecker-valid-",
			},
			Spec: cmapi.CertificateRequestSpec{
				Request: csrPEM.Bytes(),
				IssuerRef: cmmeta.ObjectReference{
					Name: "cmapichecker",
				},
			},
		},
		testInvalidCR: &cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "cmapichecker-invalid-",
			},
			Spec: cmapi.CertificateRequestSpec{
				Request: []byte("invalid-csr"),
				IssuerRef: cmmeta.ObjectReference{
					Name: "cmapichecker",
				},
			},
		},
	}, nil
}

// Check attempts to perform a dry-run create of a cert-manager
// Certificate resource in order to verify that CRDs are installed and all the
// required webhooks are reachable by the K8S API server.
// Originally we used the v1alpha2 API to ensure that the API server has also
// connected to the cert-manager conversion webhook, but since cert-manager 1.6
// we have disabled the serving of non-v1 CRD versions, so it is no longer
// possible to test the reachability of the conversion webhook.
func (o *cmapiChecker) Check(ctx context.Context) error {
	// Test the mutating webhook, which should add the username, UID, and groups
	if err := func() error {
		certReq := o.testValidCR.DeepCopy()
		if err := o.client.Create(ctx, certReq); err != nil {
			return err
		}

		if certReq.Spec.Username == "" &&
			certReq.Spec.UID == "" {
			return ErrMutationWebhookMissing
		}

		return nil
	}(); err != nil {
		return err
	}

	// Test the validating webhook, which should reject the request
	if err := func() error {
		certReq := o.testInvalidCR.DeepCopy()
		if err := o.client.Create(ctx, certReq); err == nil {
			return ErrValidatingWebhookMissing
		} else if !regexErrCertmanagerDeniedRequest.MatchString(err.Error()) {
			return err
		}

		return nil
	}(); err != nil {
		return err
	}

	return nil
}

// TranslateToSimpleError detects errors based on the error message.
// It tries to map these error messages to a better understandable error message that
// explains what is wrong. If it cannot create a simple error, it will return nil.
// ErrCertManagerCRDsNotFound:
// - error finding the scope of the object: failed to get restmapping: no matches for kind "Certificate" in group "cert-manager.io"
// ErrWebhookServiceFailure:
// - Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": service "cert-manager-webhook" not found
// ErrWebhookDeploymentFailure:
// - Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.38.90:443: connect: connection refused
// ErrWebhookCertificateFailure:
// - Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": x509: certificate signed by unknown authority (possibly because of "x509: ECDSA verification failure" while trying to verify candidate authority certificate "cert-manager-webhook-ca")
// ErrMutationWebhookIncorrect:
// - admission webhook "webhook.cert-manager.io" denied the request: [spec.username: Forbidden: username identity must be that of the requester, spec.groups: Forbidden: groups identity must be that of the requester]
// ErrFailedToCheckAPI:
// - certificaterequests.cert-manager.io is forbidden: User "test" cannot create resource "certificaterequests" in API group "cert-manager.io" in the namespace "default"
// - admission webhook "validate.kyverno.svc-fail" denied the request: ...
func TranslateToSimpleError(err error) error {
	if err == nil {
		return nil
	}

	s := err.Error()
	switch {
	case regexErrCertManagerCRDsNotFound1.MatchString(s) ||
		regexErrCertManagerCRDsNotFound2.MatchString(s) ||
		regexErrCertManagerCRDsNotFound3.MatchString(s) ||
		regexErrCertManagerCRDsNotFound4.MatchString(s) ||
		regexErrCertManagerCRDsNotFound5.MatchString(s):
		return ErrCertManagerCRDsNotFound
	case regexErrWebhookServiceFailure.MatchString(s):
		return ErrWebhookServiceFailure
	case regexErrWebhookDeploymentFailure.MatchString(s):
		return ErrWebhookDeploymentFailure
	case regexErrWebhookCertificateFailure.MatchString(s):
		return ErrWebhookCertificateFailure
	case regexErrCertmanagerDeniedRequest.MatchString(s):
		return ErrMutationWebhookIncorrect
	case regexErrForbidden.MatchString(s) ||
		regexErrDenied.MatchString(s):
		return ErrFailedToCheckAPI
	default:
		return nil
	}
}
