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

// feature contains controller's feature gate setup functionality. Do not import
// this package into any code that's shared with other components to prevent
// overwriting other component's feature gates, see i.e
// https://github.com/cert-manager/cert-manager/issues/6011
package feature

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/component-base/featuregate"

	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

// see https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/#feature-stages

const (
	// Copy & paste the following template when you add a new feature gate:
	// ========================== START TEMPLATE ==========================
	// Owner: @username
	// Alpha: vX.Y
	// Beta: ...
	//
	// FeatureName will enable XYZ feature.
	// Fill this section out with additional details about the feature.
	// FeatureName featuregate.Feature = "FeatureName"
	// =========================== END TEMPLATE ===========================

	// Owner: N/A
	// Alpha: v0.7.2
	//
	// ValidateCAA enables CAA checking when issuing certificates
	ValidateCAA featuregate.Feature = "ValidateCAA"

	// Owner: N/A
	// Alpha: v1.4
	//
	// ExperimentalCertificateSigningRequestControllers enables all CertificateSigningRequest
	// controllers that sign Kubernetes CertificateSigningRequest resources
	ExperimentalCertificateSigningRequestControllers featuregate.Feature = "ExperimentalCertificateSigningRequestControllers"

	// Owner: N/A
	// Alpha: v1.5
	// Beta: v1.15
	//
	// ExperimentalGatewayAPISupport enables the gateway-shim controller and adds support for
	// the Gateway API to the HTTP-01 challenge solver.
	ExperimentalGatewayAPISupport featuregate.Feature = "ExperimentalGatewayAPISupport"

	// Owner: @joshvanl
	// Alpha: v1.7
	// Beta: v1.15
	//
	// AdditionalCertificateOutputFormats enable output additional format
	AdditionalCertificateOutputFormats featuregate.Feature = "AdditionalCertificateOutputFormats"

	// Owner: @joshvanl
	// Alpha: v1.8
	//
	// ServerSideApply enables the use of ServerSideApply in all API calls.
	ServerSideApply featuregate.Feature = "ServerSideApply"

	// Owner: @spockz , @irbekrm
	// Alpha: v1.9
	//
	// LiteralCertificateSubject will enable providing a subject in the Certificate that will be used literally in the CertificateSigningRequest. The subject can be provided via `LiteralSubject` field on `Certificate`'s spec.
	// This feature gate must be used together with LiteralCertificateSubject webhook feature gate.
	// See https://github.com/cert-manager/cert-manager/issues/3203 and https://github.com/cert-manager/cert-manager/issues/4424 for context.
	LiteralCertificateSubject featuregate.Feature = "LiteralCertificateSubject"

	// Owner: @inteon
	// Alpha: v1.10
	// Beta: v1.13
	//
	// StableCertificateRequestName will enable generation of CertificateRequest resources with a fixed name. The name of the CertificateRequest will be a function of Certificate resource name and its revision
	// This feature gate will disable auto-generated CertificateRequest name
	// Github Issue: https://github.com/cert-manager/cert-manager/issues/4956
	StableCertificateRequestName featuregate.Feature = "StableCertificateRequestName"

	// Owner: @SgtCoDFish
	// Alpha: v1.11
	//
	// UseCertificateRequestBasicConstraints will add Basic Constraints section in the Extension Request of the Certificate Signing Request
	// This feature will add BasicConstraints section with CA field defaulting to false; CA field will be set true if the Certificate resource spec has isCA as true
	// Github Issue: https://github.com/cert-manager/cert-manager/issues/5539
	UseCertificateRequestBasicConstraints featuregate.Feature = "UseCertificateRequestBasicConstraints"

	// Owner: @irbekrm
	// Alpha v1.12
	// Beta: v1.13
	//
	// SecretsFilteredCaching reduces controller's memory consumption by
	// filtering which Secrets are cached in full using
	// `controller.cert-manager.io/fao` label. By default all Certificate
	// Secrets are labelled with controller.cert-manager.io/fao label. Users
	// can also label other Secrets, such as issuer credentials Secrets that
	// they know cert-manager will need to access, to speed up issuance.
	// See https://github.com/cert-manager/cert-manager/blob/master/design/20221205-memory-management.md
	SecretsFilteredCaching featuregate.Feature = "SecretsFilteredCaching"

	// Owner: @inteon
	// Beta: v1.13
	// GA: v1.15
	//
	// DisallowInsecureCSRUsageDefinition will prevent the webhook from allowing
	// CertificateRequest's usages to be only defined in the CSR, while leaving
	// the usages field empty.
	DisallowInsecureCSRUsageDefinition featuregate.Feature = "DisallowInsecureCSRUsageDefinition"

	// Owner: @tanujd11
	// Alpha: v1.14
	//
	// NameConstraints adds support for Name Constraints in Certificate resources
	// with IsCA=true.
	// Github Issue: https://github.com/cert-manager/cert-manager/issues/3655
	NameConstraints featuregate.Feature = "NameConstraints"

	// Owner: @SpectralHiss
	// Alpha: v1.14
	//
	// OtherNames adds support for OtherName Subject Alternative Name values in
	// Certificate resources.
	// Github Issue: https://github.com/cert-manager/cert-manager/issues/6393
	OtherNames featuregate.Feature = "OtherNames"

	// Owner: @jsoref
	// Alpha: v1.16
	//
	// UseDomainQualifiedFinalizer changes the finalizer added to cert-manager created
	// resources to acme.cert-manager.io/finalizer instead of finalizer.acme.cert-manager.io.
	// GitHub Issue: https://github.com/cert-manager/cert-manager/issues/7266
	UseDomainQualifiedFinalizer featuregate.Feature = "UseDomainQualifiedFinalizer"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(defaultCertManagerFeatureGates))
}

// defaultCertManagerFeatureGates consists of all known cert-manager feature keys.
// To add a new feature, define a key for it above and add it here. The features will be
// available on the cert-manager controller binary.
var defaultCertManagerFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	DisallowInsecureCSRUsageDefinition: {Default: true, PreRelease: featuregate.GA},
	StableCertificateRequestName:       {Default: true, PreRelease: featuregate.Beta},
	SecretsFilteredCaching:             {Default: true, PreRelease: featuregate.Beta},

	ValidateCAA: {Default: false, PreRelease: featuregate.Alpha},
	ExperimentalCertificateSigningRequestControllers: {Default: false, PreRelease: featuregate.Alpha},
	ExperimentalGatewayAPISupport:                    {Default: true, PreRelease: featuregate.Beta},
	AdditionalCertificateOutputFormats:               {Default: true, PreRelease: featuregate.Beta},
	ServerSideApply:                                  {Default: false, PreRelease: featuregate.Alpha},
	LiteralCertificateSubject:                        {Default: true, PreRelease: featuregate.Beta},
	UseCertificateRequestBasicConstraints:            {Default: false, PreRelease: featuregate.Alpha},
	NameConstraints:                                  {Default: false, PreRelease: featuregate.Alpha},
	OtherNames:                                       {Default: false, PreRelease: featuregate.Alpha},
	UseDomainQualifiedFinalizer:                      {Default: false, PreRelease: featuregate.Alpha},
}
