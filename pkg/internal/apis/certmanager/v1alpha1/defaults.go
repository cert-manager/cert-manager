/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

func SetDefaults_Certificate(obj *v1alpha1.Certificate) {
	if obj.Spec.IssuerRef.Kind == "" {
		obj.Spec.IssuerRef.Kind = v1alpha1.IssuerKind
	}
	if obj.Spec.RenewBefore == nil {
		obj.Spec.RenewBefore = &metav1.Duration{Duration: v1alpha1.DefaultRenewBefore}
	}
}

func SetDefaults_CertificateRequest(obj *v1alpha1.CertificateRequest) {
	if obj.Spec.IssuerRef.Kind == "" {
		obj.Spec.IssuerRef.Kind = v1alpha1.IssuerKind
	}
}

func SetDefaults_Order(obj *v1alpha1.Order) {
	if obj.Spec.IssuerRef.Kind == "" {
		obj.Spec.IssuerRef.Kind = v1alpha1.IssuerKind
	}
}

func SetDefaults_Challenge(obj *v1alpha1.Challenge) {
	if obj.Spec.IssuerRef.Kind == "" {
		obj.Spec.IssuerRef.Kind = v1alpha1.IssuerKind
	}
}
