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

package certificates

import (
	"fmt"

	. "github.com/onsi/ginkgo"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/jetstack/cert-manager/test/e2e/framework/helper/validation/certificates"
)

// Suite defines a reusable conformance test suite that can be used against any
// Issuer implementation.
type Suite struct {
	// Name is the name of the issuer being tested, e.g. SelfSigned, CA, ACME
	// This field must be provided.
	Name string

	// CreateIssuerFunc is a function that provisions a new issuer resource and
	// returns an ObjectReference to that Issuer that will be used as the
	// IssuerRef on Certificate resources that this suite creates.
	// This field must be provided.
	CreateIssuerFunc func(*framework.Framework) cmmeta.ObjectReference

	// DeleteIssuerFunc is a function that is run after the test has completed
	// in order to clean up resources created for a test (e.g. the resources
	// created in CreateIssuerFunc).
	// This function will be run regardless whether the test passes or fails.
	// If not specified, this function will be skipped.
	DeleteIssuerFunc func(*framework.Framework, cmmeta.ObjectReference)

	// DomainSuffix is a suffix used on all domain requests.
	// This is useful when the issuer being tested requires special
	// configuration for a set of domains in order for certificates to be
	// issued, such as the ACME issuer.
	// If not set, this will be defaulted to the configured 'domain' for the
	// nginx-ingress addon.
	DomainSuffix string

	// HTTP01TestType is set to "Ingress" or "Gateway" to determine which IPs
	// and Domains will be used to run the ACME HTTP-01 test suites.
	HTTP01TestType string

	// UnsupportedFeatures is a list of features that are not supported by this
	// invocation of the test suite.
	// This is useful if a particular issuers explicitly does not support
	// certain features due to restrictions in their implementation.
	UnsupportedFeatures featureset.FeatureSet

	// RequiredFeatures is a list of features that, if not empty, denote tests
	// where _all_ of these features must be present for that test to execute.
	// Useful for Issuers that require certain fields to be present for that
	// Issuer to accept and sign the Certificate.
	RequiredFeatures featureset.FeatureSet

	// ExtraValidations are extra validations that should be performed for _all_
	// executed test cases in this suite. Useful for Issuers that require extra
	// validation to be performed against features that are not expressed by the
	// Certificate API. Has no effect on existing validations performed by each
	// test case.
	ExtraValidations []certificates.ValidationFunc

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
		switch s.HTTP01TestType {
		case "Ingress":
			s.DomainSuffix = f.Config.Addons.IngressController.Domain
		case "Gateway":
			s.DomainSuffix = f.Config.Addons.Gateway.Domain
		}
	}

	if s.UnsupportedFeatures == nil {
		s.UnsupportedFeatures = make(featureset.FeatureSet)
	}

	s.completed = true
}

// it is called by the tests to in Define() to setup and run the test
func (s *Suite) it(f *framework.Framework, name string, fn func(cmmeta.ObjectReference), requiredFeatures ...featureset.Feature) {
	if !s.checkUnsupportedFeatures(requiredFeatures...) {
		fmt.Fprintln(GinkgoWriter, "skipping case due to unsupported features")
		return
	}

	if !s.checkRequiredFeatures(featureset.NewFeatureSet(requiredFeatures...)) {
		fmt.Fprintln(GinkgoWriter, "skipping case due to missing required features")
		return
	}

	It(name, func() {
		By("Creating an issuer resource")
		issuerRef := s.CreateIssuerFunc(f)
		defer func() {
			if s.DeleteIssuerFunc != nil {
				By("Cleaning up the issuer resource")
				s.DeleteIssuerFunc(f, issuerRef)
			}
		}()
		fn(issuerRef)
	})
}

// checkUnsupportedFeatures is a helper function that is used to ensure that
// the features required for a given test case are supported by the suite.  It
// will return 'true' if all features are supported and the test should run, or
// return 'false' if any required feature is not supported.
func (s *Suite) checkUnsupportedFeatures(fs ...featureset.Feature) bool {
	unsupported := make(featureset.FeatureSet)
	for _, f := range fs {
		if s.UnsupportedFeatures.Contains(f) {
			unsupported.Add(f)
		}
	}
	// all features supported, return early!
	if len(unsupported) == 0 {
		return true
	}
	return false
}

// checkRequiredFeatures is a helper function that is used to ensure that the
// features required for a given suite are present of a given test. Will return
// 'true' if all RequiredFeatures features are present and the test should
// run. Returns 'false' if there are any features which are missing for this
// test. Always returns 'true' if RequiredFeatures is empty.
func (s *Suite) checkRequiredFeatures(fs featureset.FeatureSet) bool {
	if len(s.RequiredFeatures) == 0 {
		return true
	}
	for _, required := range s.RequiredFeatures.List() {
		if !fs.Contains(required) {
			return false
		}
	}
	return true
}
