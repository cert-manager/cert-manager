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
	"fmt"

	errors "github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
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

// VersionChecker implements a version checker using a controller-runtime client
type VersionChecker struct {
	client client.Client

	versionSources map[string]string
}

// New returns a cert-manager version checker. Prefer New over NewFromClient
// since New will ensure the scheme is configured correctly.
func New(restcfg *rest.Config, scheme *runtime.Scheme) (*VersionChecker, error) {
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	if err := apiextensionsv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	cl, err := client.New(restcfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, err
	}

	return &VersionChecker{
		client:         cl,
		versionSources: map[string]string{},
	}, nil
}

// NewFromClient initialises a VersionChecker using the given client. Prefer New
// instead, which will ensure that the scheme on the client is configured correctly.
func NewFromClient(cl client.Client) *VersionChecker {
	return &VersionChecker{
		client:         cl,
		versionSources: map[string]string{},
	}
}

// Version determines the installed cert-manager version. First, we look for
// the "certificates.cert-manager.io" CRD and try to extract the version from that
// resource's labels. Then, if it uses a webhook, that webhook service resource's
// labels are checked for a label. Lastly the pods linked to the webhook its labels
// are checked and the image tag is used to determine the version.
// If no "certificates.cert-manager.io" CRD is found, the older
// "certificates.certmanager.k8s.io" CRD is tried too.
func (o *VersionChecker) Version(ctx context.Context) (*Version, error) {
	// Use the "certificates.cert-manager.io" CRD as a starting point
	err := o.extractVersionFromCrd(ctx, certificatesCertManagerCrdName)

	if err != nil && errors.Is(err, ErrCertManagerCRDsNotFound) {
		// Retry using the old CRD name "certificates.certmanager.k8s.io" as
		// a starting point and overwrite ErrCertManagerCRDsNotFound error
		err = o.extractVersionFromCrd(ctx, certificatesCertManagerOldCrdName)
	}

	// From the found versions, now determine if we have found any/
	// if they are all the same version
	version, detectionError := o.determineVersion()

	if err != nil && detectionError != nil {
		// There was an error while determining the version (which is probably
		// caused by a bad setup/ permission or networking issue) and there also
		// was an error while trying to reduce the found versions to 1 version
		// Display both.
		err = fmt.Errorf("%v: %v", detectionError, err)
	} else if detectionError != nil {
		// An error occured while trying to reduce the found versions to 1 version
		err = detectionError
	}

	return version, err
}

// determineVersion attempts to determine the version of the cert-manager install based on all found
// versions. The function tries to reduce the found versions to 1 correct version.
// An error is returned if no sources were found or if multiple different versions
// were found.
func (o *VersionChecker) determineVersion() (*Version, error) {
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
