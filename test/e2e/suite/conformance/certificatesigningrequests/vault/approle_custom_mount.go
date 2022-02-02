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

package vault

import (
	"github.com/cert-manager/cert-manager/test/e2e/framework"
	"github.com/cert-manager/cert-manager/test/e2e/framework/helper/featureset"
	"github.com/cert-manager/cert-manager/test/e2e/suite/conformance/certificatesigningrequests"
)

var _ = framework.ConformanceDescribe("CertificateSigningRequests", func() {
	issuer := &approle{
		testWithRootCA: true,
		authPath:       customAuthPath,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault AppRole Custom Auth Path Issuer With Root CA",
		CreateIssuerFunc: issuer.createIssuer,
		DeleteIssuerFunc: issuer.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()

	issuerNoRoot := &approle{
		testWithRootCA: false,
		authPath:       customAuthPath,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault AppRole Custom Auth Path Issuer Without Root CA",
		CreateIssuerFunc: issuerNoRoot.createIssuer,
		DeleteIssuerFunc: issuerNoRoot.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()

	clusterIssuer := &approle{
		testWithRootCA: true,
		authPath:       customAuthPath,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault AppRole Custom Auth Path ClusterIssuer With Root CA",
		CreateIssuerFunc: clusterIssuer.createClusterIssuer,
		DeleteIssuerFunc: clusterIssuer.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()

	clusterIssuerNoRoot := &approle{
		testWithRootCA: false,
		authPath:       customAuthPath,
	}
	(&certificatesigningrequests.Suite{
		Name:             "Vault AppRole Custom Auth Path ClusterIssuer Without Root CA",
		CreateIssuerFunc: clusterIssuerNoRoot.createClusterIssuer,
		DeleteIssuerFunc: clusterIssuerNoRoot.delete,
		UnsupportedFeatures: featureset.NewFeatureSet(
			featureset.KeyUsagesFeature,
			featureset.Ed25519FeatureSet,
		),
	}).Define()
})
