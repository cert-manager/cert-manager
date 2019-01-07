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

package gen

import (
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

type IssuerModifier func(v1alpha1.GenericIssuer)

func ClusterIssuer(name string, mods ...IssuerModifier) *v1alpha1.ClusterIssuer {
	c := &v1alpha1.ClusterIssuer{
		ObjectMeta: ObjectMeta(name),
	}
	c.ObjectMeta.Namespace = ""
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func ClusterIssuerFrom(iss *v1alpha1.ClusterIssuer, mods ...IssuerModifier) *v1alpha1.ClusterIssuer {
	for _, mod := range mods {
		mod(iss)
	}
	return iss
}

func Issuer(name string, mods ...IssuerModifier) *v1alpha1.Issuer {
	c := &v1alpha1.Issuer{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func IssuerFrom(iss *v1alpha1.Issuer, mods ...IssuerModifier) *v1alpha1.Issuer {
	for _, mod := range mods {
		mod(iss)
	}
	return iss
}

func SetIssuerACME(a v1alpha1.ACMEIssuer) IssuerModifier {
	return func(iss v1alpha1.GenericIssuer) {
		iss.GetSpec().ACME = &a
	}
}

func SetIssuerCA(a v1alpha1.CAIssuer) IssuerModifier {
	return func(iss v1alpha1.GenericIssuer) {
		iss.GetSpec().CA = &a
	}
}

func SetIssuerSelfSigned(a v1alpha1.SelfSignedIssuer) IssuerModifier {
	return func(iss v1alpha1.GenericIssuer) {
		iss.GetSpec().SelfSigned = &a
	}
}

func AddIssuerCondition(c v1alpha1.IssuerCondition) IssuerModifier {
	return func(iss v1alpha1.GenericIssuer) {
		iss.GetStatus().Conditions = append(iss.GetStatus().Conditions, c)
	}
}
