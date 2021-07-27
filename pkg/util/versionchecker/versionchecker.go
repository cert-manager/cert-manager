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

package versionchecker

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacv1beta1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	errors "github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const certificatesCertManagerCrdName = "certificates.cert-manager.io"
const certificatesCertManagerOldCrdName = "certificates.certmanager.k8s.io"

var certManagerLabelSelector = map[string]string{
	"app.kubernetes.io/instance": "cert-manager",
}
var certManagerOldLabelSelector = map[string]string{
	"release": "cert-manager",
}

var (
	ErrCertManagerCRDsNotFound = errors.New("the cert-manager CRDs are not yet installed on the Kubernetes API server")
	ErrVersionNotDetected      = errors.New("could not detect the cert-manager version")
)

func shouldReturn(err error) bool {
	return (err == nil) || (!errors.Is(err, ErrVersionNotDetected))
}

// Interface is used to check what cert-manager version is installed
type Interface interface {
	Version(context.Context) (string, error)
}

type versionChecker struct {
	client client.Client
}

// New returns a cert-manager version checker
func New(restcfg *rest.Config, scheme *runtime.Scheme) (Interface, error) {
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextensionsv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := rbacv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	cl, err := client.New(restcfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, err
	}
	return &versionChecker{
		client: cl,
	}, nil
}

func (o *versionChecker) Version(ctx context.Context) (string, error) {
	version, err := o.extractVersionFromCrd(ctx, certificatesCertManagerCrdName)
	if (err == nil) || (!errors.Is(err, ErrVersionNotDetected) && !errors.Is(err, ErrCertManagerCRDsNotFound)) {
		return version, err
	}

	if errors.Is(err, ErrCertManagerCRDsNotFound) {
		if version, err = o.extractVersionFromCrd(ctx, certificatesCertManagerOldCrdName); shouldReturn(err) {
			return version, err
		}
	}

	return "", err
}
