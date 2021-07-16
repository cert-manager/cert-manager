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
	"context"
	"fmt"
	"regexp"

	errors "github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	// Use v1alpha2 API to ensure that the API server has also connected to the
	// cert-manager conversion webhook.
	// TODO(wallrj): Only change this when the old deprecated APIs are removed,
	// at which point the conversion webhook may be removed anyway.
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

var (
	ErrCertManagerCRDsNotFound   = errors.New("the cert-manager CRDs are not yet installed on the Kubernetes API server")
	ErrWebhookServiceFailure     = errors.New("the cert-manager webhook service is not created yet")
	ErrWebhookDeploymentFailure  = errors.New("the cert-manager webhook deployment is not ready yet")
	ErrWebhookCertificateFailure = errors.New("the cert-manager webhook CA bundle is not injected yet")
)

const (
	crdsMappingError  = `error finding the scope of the object: failed to get restmapping: no matches for kind "Certificate" in group "cert-manager.io"`
	crdsNotFoundError = `the server could not find the requested resource (post certificates.cert-manager.io)`
)

var (
	regexErrCertManagerCRDsNotFound   = regexp.MustCompile(`^(` + regexp.QuoteMeta(crdsMappingError) + `|` + regexp.QuoteMeta(crdsNotFoundError) + `)$`)
	regexErrWebhookServiceFailure     = regexp.MustCompile(`Post "(.*)": service "(.*)-webhook" not found`)
	regexErrWebhookDeploymentFailure  = regexp.MustCompile(`Post "(.*)": (.*): connect: connection refused`)
	regexErrWebhookCertificateFailure = regexp.MustCompile(`Post "(.*)": x509: certificate signed by unknown authority`)
)

// Interface is used to check that the cert-manager CRDs have been installed and are usable.
type Interface interface {
	Check(context.Context) error
}

type cmapiChecker struct {
	client client.Client
}

// New returns a cert-manager API checker
func New(restcfg *rest.Config, scheme *runtime.Scheme, namespace string) (Interface, error) {
	if err := cmapi.AddToScheme(scheme); err != nil {
		return nil, errors.Wrap(err, "while configuring scheme")
	}

	cl, err := client.New(restcfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, errors.Wrap(err, "while creating client")
	}

	return &cmapiChecker{
		client: client.NewNamespacedClient(client.NewDryRunClient(cl), namespace),
	}, nil
}

// Check attempts to perform a dry-run create of a cert-manager *v1alpha2*
// Certificate resource in order to verify that CRDs are installed and all the
// required webhooks are reachable by the K8S API server.
// We use v1alpha2 API to ensure that the API server has also connected to the
// cert-manager conversion webhook.
func (o *cmapiChecker) Check(ctx context.Context) error {
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cmapichecker-",
		},
		Spec: cmapi.CertificateSpec{
			DNSNames:   []string{"cmapichecker.example"},
			SecretName: "cmapichecker",
			IssuerRef: cmmeta.ObjectReference{
				Name: "cmapichecker",
			},
		},
	}

	if err := o.client.Create(ctx, cert); err != nil {
		return &ApiCheckError{
			SimpleError:     translateToSimpleError(err),
			UnderlyingError: err,
		}
	}
	return nil
}

type ApiCheckError struct {
	SimpleError     error
	UnderlyingError error
}

func (e *ApiCheckError) Error() string {
	// If no simple error exists, print underlying error
	if e.SimpleError == nil {
		return e.UnderlyingError.Error()
	}
	return fmt.Sprintf("%v (%v)", e.SimpleError.Error(), e.UnderlyingError.Error())
}

// If no simple error exists, this function will return nil
// which indicates that the error is not unwrappable
func (e *ApiCheckError) Unwrap() error {
	return e.SimpleError
}

// This translateToSimpleError function detects errors based on the error message.
// It tries to map these error messages to a better understandable error message that
// explains what is wrong. If it cannot create a simple error, it will return nil.
// ErrCertManagerCRDsNotFound:
// - error finding the scope of the object: failed to get restmapping: no matches for kind "Certificate" in group "cert-manager.io"
// ErrWebhookServiceFailure:
// - Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": service "cert-manager-webhook" not found
// - conversion webhook for cert-manager.io/v1alpha2, Kind=Certificate failed: Post "https://cert-manager-webhook.cert-manager.svc:443/convert?timeout=30s": service "cert-manager-webhook" not found
// ErrWebhookDeploymentFailure:
// - Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.38.90:443: connect: connection refused
// - conversion webhook for cert-manager.io/v1alpha2, Kind=Certificate failed: Post "https://cert-manager-webhook.cert-manager.svc:443/convert?timeout=30s": dial tcp 10.96.38.90:443: connect: connection refused
// ErrWebhookCertificateFailure:
// - Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": x509: certificate signed by unknown authority (possibly because of "x509: ECDSA verification failure" while trying to verify candidate authority certificate "cert-manager-webhook-ca")
// - conversion webhook for cert-manager.io/v1alpha2, Kind=Certificate failed: Post "https://cert-manager-webhook.cert-manager.svc:443/convert?timeout=30s": x509: certificate signed by unknown authority
func translateToSimpleError(err error) error {
	s := err.Error()

	if regexErrCertManagerCRDsNotFound.MatchString(s) {
		return ErrCertManagerCRDsNotFound
	} else if regexErrWebhookServiceFailure.MatchString(s) {
		return ErrWebhookServiceFailure
	} else if regexErrWebhookDeploymentFailure.MatchString(s) {
		return ErrWebhookDeploymentFailure
	} else if regexErrWebhookCertificateFailure.MatchString(s) {
		return ErrWebhookCertificateFailure
	}

	return nil
}
