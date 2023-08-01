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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

var (
	ErrCertManagerCRDsNotFound   = fmt.Errorf("the cert-manager CRDs are not yet installed on the Kubernetes API server")
	ErrWebhookServiceFailure     = fmt.Errorf("the cert-manager webhook service is not created yet")
	ErrWebhookDeploymentFailure  = fmt.Errorf("the cert-manager webhook deployment is not ready yet")
	ErrWebhookCertificateFailure = fmt.Errorf("the cert-manager webhook CA bundle is not injected yet")
)

const (
	crdsMapping1Error = `error finding the scope of the object: failed to get restmapping: failed to find API group "cert-manager.io"`
	crdsMapping2Error = `error finding the scope of the object: failed to get restmapping: no matches for kind "Certificate" in group "cert-manager.io"`
	crdsNotFoundError = `the server could not find the requested resource (post certificates.cert-manager.io)`
)

var (
	regexErrCertManagerCRDsNotFound   = regexp.MustCompile(`^(` + regexp.QuoteMeta(crdsMapping1Error) + `|` + regexp.QuoteMeta(crdsMapping2Error) + `|` + regexp.QuoteMeta(crdsNotFoundError) + `)$`)
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
		return nil, fmt.Errorf("while configuring scheme: %w", err)
	}

	cl, err := client.New(restcfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, fmt.Errorf("while creating client: %w", err)
	}

	return &cmapiChecker{
		client: client.NewNamespacedClient(client.NewDryRunClient(cl), namespace),
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
func TranslateToSimpleError(err error) error {
	s := err.Error()

	switch {
	case regexErrCertManagerCRDsNotFound.MatchString(s):
		return ErrCertManagerCRDsNotFound
	case regexErrWebhookServiceFailure.MatchString(s):
		return ErrWebhookServiceFailure
	case regexErrWebhookDeploymentFailure.MatchString(s):
		return ErrWebhookDeploymentFailure
	case regexErrWebhookCertificateFailure.MatchString(s):
		return ErrWebhookCertificateFailure
	default:
		return nil
	}
}
