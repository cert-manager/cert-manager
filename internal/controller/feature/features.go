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

package feature

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/featuregate"

	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

const (
	// alpha: v0.7.2
	//
	// ValidateCAA enables CAA checking when issuing certificates
	ValidateCAA featuregate.Feature = "ValidateCAA"

	// alpha: v1.4.0
	//
	// ExperimentalCertificateSigningRequestControllers enables all CertificateSigningRequest
	// controllers that sign Kubernetes CertificateSigningRequest resources
	ExperimentalCertificateSigningRequestControllers featuregate.Feature = "ExperimentalCertificateSigningRequestControllers"

	// alpha: v1.5.0
	//
	// ExperimentalGatewayAPISupport enables the gateway-shim controller and adds support for
	// the Gateway API to the HTTP-01 challenge solver.
	ExperimentalGatewayAPISupport featuregate.Feature = "ExperimentalGatewayAPISupport"

	// Owner: @joshvanl
	// alpha: v1.7.0
	//
	// AdditionalCertificateOutputFormats enable output additional format
	// See https://github.com/cert-manager/cert-manager/blob/master/design/20220118.server-side-apply.md#feature-gate
	AdditionalCertificateOutputFormats featuregate.Feature = "AdditionalCertificateOutputFormats"

	// alpha: v1.8.0
	//
	// ServerSideApply enables the use of ServerSideApply in all API calls.
	ServerSideApply featuregate.Feature = "ServerSideApply"

	// Owner (responsible for graduating feature through to GA): @spockz , @irbekrm
	// Alpha: v1.9
	// LiteralCertificateSubject will enable providing a subject in the Certificate that will be used literally in the CertificateSigningRequest. The subject can be provided via `LiteralSubject` field on `Certificate`'s spec.
	// This feature gate must be used together with LiteralCertificateSubject webhook feature gate.
	// See https://github.com/cert-manager/cert-manager/issues/3203 and https://github.com/cert-manager/cert-manager/issues/4424 for context.
	LiteralCertificateSubject featuregate.Feature = "LiteralCertificateSubject"

	// Alpha: v1.10
	// StableCertificateRequestName will enable generation of CertificateRequest resources with a fixed name. The name of the CertificateRequest will be a function of Certificate resource name and its revision
	// This feature gate will disable auto-generated CertificateRequest name
	// Github Issue: https://github.com/cert-manager/cert-manager/issues/4956
	StableCertificateRequestName featuregate.Feature = "StableCertificateRequestName"

	// Alpha: v1.11
	// UseCertificateRequestBasicConstraints will add Basic Constraints section in the Extension Request of the Certificate Signing Request
	// This feature will add BasicConstraints section with CA field defaulting to false; CA field will be set true if the Certificate resource spec has isCA as true
	// Github Issue: https://github.com/cert-manager/cert-manager/issues/5539
	UseCertificateRequestBasicConstraints featuregate.Feature = "UseCertificateRequestBasicConstraints"

	// Owner: @irbekrm
	// Alpha v1.12
	// SecretsFilteredCaching reduces controller's memory consumption by
	// filtering which Secrets are cached in full using
	// `controller.cert-manager.io/fao` label. By default all Certificate
	// Secrets are labelled with controller.cert-manager.io/fao label. Users
	// can also label other Secrets, such as issuer credentials Secrets that
	// they know cert-manager will need access to to speed up issuance.
	// See https://github.com/cert-manager/cert-manager/blob/master/design/20221205-memory-management.md
	SecretsFilteredCaching featuregate.Feature = "SecretsFilteredCaching"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultCertManagerFeatureGates))
}

// defaultCertManagerFeatureGates consists of all known cert-manager feature keys.
// To add a new feature, define a key for it above and add it here. The features will be
// available on the cert-manager controller binary.
var defaultCertManagerFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	ValidateCAA: {Default: false, PreRelease: featuregate.Alpha},
	ExperimentalCertificateSigningRequestControllers: {Default: false, PreRelease: featuregate.Alpha},
	ExperimentalGatewayAPISupport:                    {Default: false, PreRelease: featuregate.Alpha},
	AdditionalCertificateOutputFormats:               {Default: false, PreRelease: featuregate.Alpha},
	LiteralCertificateSubject:                        {Default: false, PreRelease: featuregate.Alpha},
	StableCertificateRequestName:                     {Default: false, PreRelease: featuregate.Alpha},
	UseCertificateRequestBasicConstraints:            {Default: false, PreRelease: featuregate.Alpha},
	// We plan to graduate this feature to Beta in v1.13 after we moved all controllers to use ServerSideApply.
	// We already know that the feature is reasonably correct & stable thanks to enabling it in our e2e tests for a while.
	// More info about criteria: https://github.com/cert-manager/cert-manager/blob/master/design/20220118.server-side-apply.md#feature-gate
	ServerSideApply: {Default: false, PreRelease: featuregate.Alpha},
	// We plan to graduate this feature to Beta in v1.13 after we gathered some User feedback.
	// More info about criteria: https://github.com/cert-manager/cert-manager/blob/master/design/20221205-memory-management.md#graduation-criteria
	SecretsFilteredCaching: {Default: false, PreRelease: featuregate.Alpha},
}
