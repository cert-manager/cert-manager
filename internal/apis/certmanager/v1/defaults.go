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

package v1

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	scheme.AddTypeDefaultingFunc(&cmapi.Certificate{}, func(obj interface{}) { SetObjectDefaults_Certificate(obj.(*cmapi.Certificate)) })
	scheme.AddTypeDefaultingFunc(&cmapi.CertificateList{}, func(obj interface{}) { SetObjectDefaults_CertificateList(obj.(*cmapi.CertificateList)) })
	scheme.AddTypeDefaultingFunc(&cmapi.CertificateRequest{}, func(obj interface{}) { SetObjectDefaults_CertificateRequest(obj.(*cmapi.CertificateRequest)) })
	scheme.AddTypeDefaultingFunc(&cmapi.CertificateRequestList{}, func(obj interface{}) {
		SetObjectDefaults_CertificateRequestList(obj.(*cmapi.CertificateRequestList))
	})
	return RegisterDefaults(scheme)
}

// SetRuntimeDefaults_Certificate mutates the supplied Certificate object,
// setting defaults for certain missing fields:
// - Sets the default  private key rotation policy to:
//   - Always, if the DefaultPrivateKeyRotationPolicyAlways feature is enabled
//   - Never, if the DefaultPrivateKeyRotationPolicyAlways feature is disabled.
//
// NOTE: Do not supply Certificate objects retrieved from a client-go lister
// because you may corrupt the cache. Do a DeepCopy first. See:
// https://pkg.go.dev/github.com/cert-manager/cert-manager@v1.17.2/pkg/client/listers/certmanager/v1#CertificateNamespaceLister
//
// NOTE: This is deliberately not called `SetObjectDefault_`, because that would
// cause defaultergen to add this to the scheme default, which would be
// confusing because we don't (yet) have a defaulting webhook or use API default
// annotations.
//
// TODO(wallrj): When DefaultPrivateKeyRotationPolicyAlways is GA, the default
// value can probably be added as an API default by adding:
//
//	`// +default="Always"`
//
// ... to the API struct.
func SetRuntimeDefaults_Certificate(in *cmapi.Certificate) {
	if in.Spec.PrivateKey == nil {
		in.Spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}
	if in.Spec.PrivateKey.RotationPolicy == "" {
		defaultRotationPolicy := cmapi.RotationPolicyNever
		if utilfeature.DefaultFeatureGate.Enabled(feature.DefaultPrivateKeyRotationPolicyAlways) {
			defaultRotationPolicy = cmapi.RotationPolicyAlways
		}
		in.Spec.PrivateKey.RotationPolicy = defaultRotationPolicy
	}
}

func SetObjectDefaults_Certificate(in *cmapi.Certificate) {
	if in.Spec.IssuerRef.Kind == "" {
		in.Spec.IssuerRef.Kind = "Issuer"
	}
	if in.Spec.IssuerRef.Group == "" {
		in.Spec.IssuerRef.Group = "cert-manager.io"
	}
}

func SetObjectDefaults_CertificateList(in *cmapi.CertificateList) {
	for i := range in.Items {
		a := &in.Items[i]
		SetObjectDefaults_Certificate(a)
	}
}

func SetObjectDefaults_CertificateRequest(in *cmapi.CertificateRequest) {
	if in.Spec.IssuerRef.Kind == "" {
		in.Spec.IssuerRef.Kind = "Issuer"
	}
	if in.Spec.IssuerRef.Group == "" {
		in.Spec.IssuerRef.Group = "cert-manager.io"
	}
}

func SetObjectDefaults_CertificateRequestList(in *cmapi.CertificateRequestList) {
	for i := range in.Items {
		a := &in.Items[i]
		SetObjectDefaults_CertificateRequest(a)
	}
}
