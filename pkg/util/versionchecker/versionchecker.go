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
	ErrCertManagerCRDsNotFound  = errors.New("the cert-manager CRDs are not yet installed on the Kubernetes API server")
	ErrVersionNotDetected       = errors.New("could not detect the cert-manager version")
	ErrMultipleVersionsDetected = errors.New("detect multiple different cert-manager versions")
)

type Version struct {
	// If all found versions are the same,
	// this field will contain that version
	Detected string `json:"detected,omitempty"`

	Sources map[string]string `json:"sources"`
}

func shouldReturn(err error) bool {
	return (err == nil) || (!errors.Is(err, ErrVersionNotDetected))
}

// Interface is used to check what cert-manager version is installed
type Interface interface {
	Version(context.Context) (*Version, error)
}

type versionChecker struct {
	client client.Client

	versionSources map[string]string
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
		client:         cl,
		versionSources: map[string]string{},
	}, nil
}

func (o *versionChecker) Version(ctx context.Context) (*Version, error) {
	err := o.extractVersionFromCrd(ctx, certificatesCertManagerCrdName)
	if err != nil && errors.Is(err, ErrCertManagerCRDsNotFound) {
		// Retry using the oldCrdName and overwrite ErrCertManagerCRDsNotFound error
		err = o.extractVersionFromCrd(ctx, certificatesCertManagerOldCrdName)
	}
	if err != nil {
		return nil, err
	}

	return o.determineVersion()
}

func (o *versionChecker) determineVersion() (*Version, error) {
	if len(o.versionSources) == 0 {
		return nil, ErrVersionNotDetected
	}

	var detectedVersion string
	for _, version := range o.versionSources {
		if detectedVersion != "" && version != detectedVersion {
			// We have found a conflicting version
			return &Version{
				Sources: o.versionSources,
			}, ErrMultipleVersionsDetected
		}

		detectedVersion = version
	}

	return &Version{
		Detected: detectedVersion,
		Sources:  o.versionSources,
	}, nil
}
