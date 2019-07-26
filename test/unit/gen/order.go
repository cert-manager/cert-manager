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

type OrderModifier func(*v1alpha1.Order)

func Order(name string, mods ...OrderModifier) *v1alpha1.Order {
	c := &v1alpha1.Order{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func OrderFrom(crt *v1alpha1.Order, mods ...OrderModifier) *v1alpha1.Order {
	crt = crt.DeepCopy()
	for _, mod := range mods {
		mod(crt)
	}
	return crt
}

// SetIssuer sets the Order.spec.issuerRef field
func SetOrderIssuer(o v1alpha1.ObjectReference) OrderModifier {
	return func(c *v1alpha1.Order) {
		c.Spec.IssuerRef = o
	}
}

func SetOrderDNSNames(dnsNames ...string) OrderModifier {
	return func(crt *v1alpha1.Order) {
		crt.Spec.DNSNames = dnsNames
	}
}

func SetOrderURL(url string) OrderModifier {
	return func(crt *v1alpha1.Order) {
		crt.Status.URL = url
	}
}

func SetOrderState(s v1alpha1.State) OrderModifier {
	return func(crt *v1alpha1.Order) {
		crt.Status.State = s
	}
}

func SetOrderCertificate(d []byte) OrderModifier {
	return func(crt *v1alpha1.Order) {
		crt.Status.Certificate = d
	}
}

func SetOrderCommonName(commonName string) OrderModifier {
	return func(crt *v1alpha1.Order) {
		crt.Spec.CommonName = commonName
	}
}

func SetOrderNamespace(namespace string) OrderModifier {
	return func(crt *v1alpha1.Order) {
		crt.ObjectMeta.Namespace = namespace
	}
}

func SetOrderDomainSolverConfig(cfg []v1alpha1.DomainSolverConfig) OrderModifier {
	return func(crt *v1alpha1.Order) {
		crt.Spec.Config = cfg
	}
}
