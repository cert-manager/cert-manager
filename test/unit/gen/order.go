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
	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

type OrderModifier func(*cmacme.Order)

func Order(name string, mods ...OrderModifier) *cmacme.Order {
	c := &cmacme.Order{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func OrderFrom(crt *cmacme.Order, mods ...OrderModifier) *cmacme.Order {
	crt = crt.DeepCopy()
	for _, mod := range mods {
		mod(crt)
	}
	return crt
}

// SetIssuer sets the Order.spec.issuerRef field
func SetOrderIssuer(o cmmeta.ObjectReference) OrderModifier {
	return func(c *cmacme.Order) {
		c.Spec.IssuerRef = o
	}
}

func SetOrderDNSNames(dnsNames ...string) OrderModifier {
	return func(crt *cmacme.Order) {
		crt.Spec.DNSNames = dnsNames
	}
}

func SetOrderURL(url string) OrderModifier {
	return func(crt *cmacme.Order) {
		crt.Status.URL = url
	}
}

func SetOrderState(s cmacme.State) OrderModifier {
	return func(crt *cmacme.Order) {
		crt.Status.State = s
	}
}

func SetOrderStatus(s cmacme.OrderStatus) OrderModifier {
	return func(o *cmacme.Order) {
		o.Status = s
	}
}

func SetOrderCertificate(d []byte) OrderModifier {
	return func(crt *cmacme.Order) {
		crt.Status.Certificate = d
	}
}

func SetOrderCommonName(commonName string) OrderModifier {
	return func(crt *cmacme.Order) {
		crt.Spec.CommonName = commonName
	}
}

func SetOrderNamespace(namespace string) OrderModifier {
	return func(crt *cmacme.Order) {
		crt.ObjectMeta.Namespace = namespace
	}
}
