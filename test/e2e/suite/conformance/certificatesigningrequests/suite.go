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

package certificatesigningrequests

import (
	"context"
	"crypto"

	certificatesv1 "k8s.io/api/certificates/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"

	. "github.com/onsi/ginkgo/v2"
)

// Suite defines a reusable conformance test suite that can be used against any
// Issuer implementation.
type Suite struct {
	// Name is the name of the issuer being tested, e.g. SelfSigned, CA, ACME
	// This field must be provided.
	Name string

	// CreateIssuerFunc is a function that provisions a new issuer resource and
	// returns an SignerName to that Issuer that will be used as the SignerName
	// on CertificateSigningRequest resources that this suite creates.
	// This field must be provided.
	CreateIssuerFunc func(context.Context, *framework.Framework) string

	// DeleteIssuerFunc is a function that is run after the test has completed
	// in order to clean up resources created for a test (e.g. the resources
	// created in CreateIssuerFunc).
	// This function will be run regardless whether the test passes or fails.
	// If not specified, this function will be skipped.
	DeleteIssuerFunc func(context.Context, *framework.Framework, string)

	// ProvisionFunc is a function that is run every test just before the
	// CertificateSigningRequest is created within a test. This is used to
	// provision or create any resources that are required by the Issuer to sign
	// the CertificateSigningRequest. This could be for example to annotate the
	// CertificateSigningRequest, or create a resource like a Secret needed for
	// signing.
	// If not specified, this function will be skipped.
	ProvisionFunc func(context.Context, *framework.Framework, *certificatesv1.CertificateSigningRequest, crypto.Signer)

	// DeProvisionFunc is run after every test. This is to be used to remove and
	// clean-up any resources which may have been created by ProvisionFunc.
	// If not specified, this function will be skipped.
	DeProvisionFunc func(context.Context, *framework.Framework, *certificatesv1.CertificateSigningRequest)

	// DomainSuffix is a suffix used on all domain requests.
	// This is useful when the issuer being tested requires special
	// configuration for a set of domains in order for certificates to be
	// issued, such as the ACME issuer.
	// If not set, this will be defaulted to the configured 'domain' for the
	// nginx-ingress addon.
	DomainSuffix string

	// UnsupportedFeatures is a list of features that are not supported by this
	// invocation of the test suite.
	// This is useful if a particular issuers explicitly does not support
	// certain features due to restrictions in their implementation.
	UnsupportedFeatures featureset.FeatureSet

	// completed is used internally to track whether Complete() has been called
	completed bool
}

// complete will validate configuration and set default values.
func (s *Suite) complete(f *framework.Framework) {
	if s.Name == "" {
		Fail("Name must be set")
	}

	if s.CreateIssuerFunc == nil {
		Fail("CreateIssuerFunc must be set")
	}

	if s.DomainSuffix == "" {
		s.DomainSuffix = f.Config.Addons.IngressController.Domain
	}

	if s.UnsupportedFeatures == nil {
		s.UnsupportedFeatures = make(featureset.FeatureSet)
	}

	s.completed = true
}

// it is called by the tests to in Define() to setup and run the test
func (s *Suite) it(f *framework.Framework, name string, fn func(context.Context, string), requiredFeatures ...featureset.Feature) {
	if s.UnsupportedFeatures.HasAny(requiredFeatures...) {
		return
	}
	It(name, func(ctx context.Context) {
		framework.RequireFeatureGate(f, utilfeature.DefaultFeatureGate, feature.ExperimentalCertificateSigningRequestControllers)

		By("Creating an issuer resource")
		signerName := s.CreateIssuerFunc(ctx, f)
		defer func() {
			if s.DeleteIssuerFunc != nil {
				By("Cleaning up the issuer resource")
				s.DeleteIssuerFunc(ctx, f, signerName)
			}
		}()
		fn(ctx, signerName)
	})
}
