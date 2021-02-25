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
	"strings"

	. "github.com/onsi/ginkgo"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
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
	// TODO: work out how to fail an entire 'Describe' block so we can validate these are correctly set
	//Expect(s.Name).NotTo(Equal(""), "Name must be set")
	//Expect(s.CreateIssuerFunc).NotTo(BeNil(), "CreateIssuerFunc must be set")

	if s.DomainSuffix == "" {
		s.DomainSuffix = f.Config.Addons.IngressController.Domain
	}

	if s.UnsupportedFeatures == nil {
		s.UnsupportedFeatures = make(featureset.FeatureSet)
	}

	s.completed = true
}

// it is called by the tests to in Define() to setup and run the test
func (s *Suite) it(f *framework.Framework, name string, fn func(cmmeta.ObjectReference), requiredFeatures ...featureset.Feature) {
	if !s.checkFeatures(requiredFeatures...) {
		fmt.Fprintln(GinkgoWriter, "skipping case due to unsupported features")
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

// checkFeatures is a helper function that is used to ensure that the features
// required for a given test case are supported by the suite.
// It will return 'true' if all features are supported and the test should run,
// or return 'false' if any required feature is not supported.
func (s *Suite) checkFeatures(fs ...featureset.Feature) bool {
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

// newDomain will generate a new random subdomain of the DomainSuffix
func (s *Suite) newDomain() string {
	return s.newDomainDepth(1)
}

// newDomainDepth return a new domain name with the given number of subdomains
// beneath the domain suffix.
// If depth is zero, the domain suffix will be returned,
// If depth is one, a random subdomain will be returned e.g. abcd.example.com,
// If depth is two, a random sub-subdomain will be returned e.g. abcd.efgh.example.com,
// and so on
func (s *Suite) newDomainDepth(depth int) string {
	subdomains := make([]string, depth)
	for i := 0; i < depth; i++ {
		subdomains[i] = util.RandStringRunes(4)
	}
	return strings.Join(append(subdomains, s.DomainSuffix), ".")
}
