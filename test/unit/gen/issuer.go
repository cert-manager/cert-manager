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

package gen

import (
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

type IssuerModifier func(v1.GenericIssuer)

func ClusterIssuer(name string, mods ...IssuerModifier) *v1.ClusterIssuer {
	c := &v1.ClusterIssuer{
		ObjectMeta: ObjectMeta(name),
	}
	c.ObjectMeta.Namespace = ""
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func ClusterIssuerFrom(iss *v1.ClusterIssuer, mods ...IssuerModifier) *v1.ClusterIssuer {
	for _, mod := range mods {
		mod(iss)
	}
	return iss
}

func Issuer(name string, mods ...IssuerModifier) *v1.Issuer {
	c := &v1.Issuer{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func IssuerFrom(iss *v1.Issuer, mods ...IssuerModifier) *v1.Issuer {
	iss = iss.DeepCopy()
	for _, mod := range mods {
		mod(iss)
	}
	return iss
}

func SetIssuerACME(a cmacme.ACMEIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().ACME = &a
	}
}

func SetIssuerCA(a v1.CAIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().CA = &a
	}
}

func SetIssuerVault(v v1.VaultIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().Vault = &v
	}
}

func SetIssuerSelfSigned(a v1.SelfSignedIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().SelfSigned = &a
	}
}

func SetIssuerVenafi(a v1.VenafiIssuer) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetSpec().Venafi = &a
	}
}

func AddIssuerCondition(c v1.IssuerCondition) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetStatus().Conditions = append(iss.GetStatus().Conditions, c)
	}
}

func SetIssuerNamespace(namespace string) IssuerModifier {
	return func(iss v1.GenericIssuer) {
		iss.GetObjectMeta().Namespace = namespace
	}
}
