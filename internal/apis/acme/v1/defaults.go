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

	acmev1 "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	scheme.AddTypeDefaultingFunc(&acmev1.Challenge{}, func(obj interface{}) { SetObjectDefaults_Challenge(obj.(*acmev1.Challenge)) })
	scheme.AddTypeDefaultingFunc(&acmev1.ChallengeList{}, func(obj interface{}) { SetObjectDefaults_ChallengeList(obj.(*acmev1.ChallengeList)) })
	scheme.AddTypeDefaultingFunc(&acmev1.Order{}, func(obj interface{}) { SetObjectDefaults_Order(obj.(*acmev1.Order)) })
	scheme.AddTypeDefaultingFunc(&acmev1.OrderList{}, func(obj interface{}) { SetObjectDefaults_OrderList(obj.(*acmev1.OrderList)) })
	return RegisterDefaults(scheme)
}

func SetObjectDefaults_Challenge(in *acmev1.Challenge) {
	if in.Spec.IssuerRef.Kind == "" {
		in.Spec.IssuerRef.Kind = "Issuer"
	}
	if in.Spec.IssuerRef.Group == "" {
		in.Spec.IssuerRef.Group = "cert-manager.io"
	}
}

func SetObjectDefaults_ChallengeList(in *acmev1.ChallengeList) {
	for i := range in.Items {
		a := &in.Items[i]
		SetObjectDefaults_Challenge(a)
	}
}

func SetObjectDefaults_Order(in *acmev1.Order) {
	if in.Spec.IssuerRef.Kind == "" {
		in.Spec.IssuerRef.Kind = "Issuer"
	}
	if in.Spec.IssuerRef.Group == "" {
		in.Spec.IssuerRef.Group = "cert-manager.io"
	}
}

func SetObjectDefaults_OrderList(in *acmev1.OrderList) {
	for i := range in.Items {
		a := &in.Items[i]
		SetObjectDefaults_Order(a)
	}
}
