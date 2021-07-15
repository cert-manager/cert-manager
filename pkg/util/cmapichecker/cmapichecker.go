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
	ErrAPIServerUnreachable                  = errors.New("unable to connect to the Kubernetes API server")
	ErrCertManagerCRDsNotFound               = errors.New("the cert-manager CRDs are not yet installed on the Kubernetes API server")
	ErrCertManagerAPIEndpointsNotEstablished = errors.New("the cert-manager API endpoints have not yet been published by the Kubernetes API server")
	ErrWebhookConnectionFailure              = errors.New("the cert-manager webhook server can't be reached yet")
	ErrWebhookCertificateFailure             = errors.New("the client CA bundle is not yet updated to the certificate of the cert-manager webhook")

	regexErrCertManagerCRDsNotFound               = regexp.MustCompile(`^error finding the scope of the object: failed to get restmapping: no matches for kind "Certificate" in group "cert-manager.io"$`)
	regexErrCertManagerAPIEndpointsNotEstablished = regexp.MustCompile(`failed calling webhook "(.*)\.cert-manager\.io": Post "(.*)\/mutate(.*)": service "(.*)-webhook" not found$`)
	regexErrWebhookConnectionFailure              = regexp.MustCompile(`failed calling webhook "(.*)\.cert-manager\.io": Post "(.*)\/mutate(.*)": (.*): connect: connection refused$`)
	regexErrWebhookCertificateFailure             = regexp.MustCompile(`Post "(.*)": x509: certificate signed by unknown authority`)
)

type ApiCheckError struct {
	SimpleError     error
	UnderlyingError error
}

func (e *ApiCheckError) Error() string {
	return e.SimpleError.Error()
}

func (e *ApiCheckError) Cause() error {
	return e.UnderlyingError
}

// Interface is used to check that the cert-manager CRDs have been installed and are usable.
type Interface interface {
	Check(context.Context) *ApiCheckError
}

type cmapiChecker struct {
	// The client controller-runtime client.New function fails if can't reach
	// the API server, so we load it lazily, to avoid breaking integration tests
	// which rely on being able to start the webhook server before the API
	// server.
	clientBuilder func() (client.Client, error)

	client client.Client
}

// New returns a cert-manager API checker
func New(restcfg *rest.Config, scheme *runtime.Scheme, namespace string) (Interface, error) {
	if err := cmapi.AddToScheme(scheme); err != nil {
		return nil, errors.Wrap(err, "while configuring scheme")
	}
	return &cmapiChecker{
		clientBuilder: func() (client.Client, error) {
			cl, err := client.New(restcfg, client.Options{
				Scheme: scheme,
			})
			if err != nil {
				return nil, errors.Wrap(err, "while creating client")
			}
			return client.NewNamespacedClient(client.NewDryRunClient(cl), namespace), nil
		},
	}, nil
}

func (o *cmapiChecker) Client() (client.Client, error) {
	if o.client != nil {
		return o.client, nil
	}

	cl, err := o.clientBuilder()
	if err != nil {
		return nil, err
	}
	o.client = cl

	return o.client, nil
}

// Check attempts to perform a dry-run create of a cert-manager *v1alpha2*
// Certificate resource in order to verify that CRDs are installed and all the
// required webhooks are reachable by the K8S API server.
// We use v1alpha2 API to ensure that the API server has also connected to the
// cert-manager conversion webhook.
func (o *cmapiChecker) Check(ctx context.Context) *ApiCheckError {
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

	// while creating client: Get "http://localhost:8080/api?timeout=32s": dial tcp 127.0.0.1:8080: connect: connection refused
	cl, err := o.Client()
	if err != nil {
		return &ApiCheckError{
			SimpleError:     ErrAPIServerUnreachable,
			UnderlyingError: err,
		}
	}

	// error finding the scope of the object: failed to get restmapping: no matches for kind "Certificate" in group "cert-manager.io"
	// Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": service "cert-manager-webhook" not found
	// Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.38.90:443: connect: connection refused
	// Internal error occurred: failed calling webhook "webhook.cert-manager.io": Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": x509: certificate signed by unknown authority (possibly because of "x509: ECDSA verification failure" while trying to verify candidate authority certificate "cert-manager-webhook-ca")
	// conversion webhook for cert-manager.io/v1alpha2, Kind=Certificate failed: Post "https://cert-manager-webhook.cert-manager.svc:443/convert?timeout=30s": x509: certificate signed by unknown authority
	if err := cl.Create(ctx, cert); err != nil {
		return &ApiCheckError{
			SimpleError:     translateToSimpleError(err),
			UnderlyingError: err,
		}
	}
	return nil
}

func translateToSimpleError(err error) error {
	s := err.Error()

	if regexErrCertManagerCRDsNotFound.MatchString(s) {
		return ErrCertManagerCRDsNotFound
	} else if regexErrCertManagerAPIEndpointsNotEstablished.MatchString(s) {
		return ErrCertManagerAPIEndpointsNotEstablished
	} else if regexErrWebhookConnectionFailure.MatchString(s) {
		return ErrWebhookConnectionFailure
	} else if regexErrWebhookCertificateFailure.MatchString(s) {
		return ErrWebhookCertificateFailure
	}

	return err
}
