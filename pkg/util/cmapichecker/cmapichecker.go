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

// Interface is used to check that the cert-manager CRDs have been installed and are usable.
type Interface interface {
	Check(context.Context) error
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
func New(restcfg *rest.Config, namespace string) (Interface, error) {
	scheme := runtime.NewScheme()
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
func (o *cmapiChecker) Check(ctx context.Context) error {
	cert := &cmapi.Certificate{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Certificate",
			APIVersion: "cert-manager.io/v1alpha2",
		},
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
	cl, err := o.Client()
	if err != nil {
		return err
	}

	if err := cl.Create(ctx, cert); err != nil {
		return errors.Wrap(err, "while attempting dry-run creation of Certificate")
	}
	return nil
}
