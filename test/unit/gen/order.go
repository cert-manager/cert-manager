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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type OrderModifier func(*cmacme.Order)

func Order(name string, mods ...OrderModifier) *cmacme.Order {
	order := &cmacme.Order{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(order)
	}
	return order
}

func OrderFrom(order *cmacme.Order, mods ...OrderModifier) *cmacme.Order {
	order = order.DeepCopy()
	for _, mod := range mods {
		mod(order)
	}
	return order
}

// SetIssuer sets the Order.spec.issuerRef field
func SetOrderIssuer(o cmmeta.ObjectReference) OrderModifier {
	return func(order *cmacme.Order) {
		order.Spec.IssuerRef = o
	}
}

func SetOrderDNSNames(dnsNames ...string) OrderModifier {
	return func(order *cmacme.Order) {
		order.Spec.DNSNames = dnsNames
	}
}

func SetOrderIPAddresses(ips ...string) OrderModifier {
	return func(order *cmacme.Order) {
		order.Spec.IPAddresses = ips
	}
}

func SetOrderURL(url string) OrderModifier {
	return func(order *cmacme.Order) {
		order.Status.URL = url
	}
}

func SetOrderState(s cmacme.State) OrderModifier {
	return func(order *cmacme.Order) {
		order.Status.State = s
	}
}

func SetOrderReason(reason string) OrderModifier {
	return func(order *cmacme.Order) {
		order.Status.Reason = reason
	}
}

func SetOrderStatus(s cmacme.OrderStatus) OrderModifier {
	return func(order *cmacme.Order) {
		order.Status = s
	}
}

func SetOrderCertificate(d []byte) OrderModifier {
	return func(order *cmacme.Order) {
		order.Status.Certificate = d
	}
}

func SetOrderCommonName(commonName string) OrderModifier {
	return func(order *cmacme.Order) {
		order.Spec.CommonName = commonName
	}
}

func SetOrderNamespace(namespace string) OrderModifier {
	return func(order *cmacme.Order) {
		order.ObjectMeta.Namespace = namespace
	}
}

func SetOrderCsr(csr []byte) OrderModifier {
	return func(order *cmacme.Order) {
		order.Spec.Request = csr
	}
}

func SetOrderDuration(duration time.Duration) OrderModifier {
	return func(order *cmacme.Order) {
		order.Spec.Duration = &metav1.Duration{Duration: duration}
	}
}

func SetOrderAnnotations(annotations map[string]string) OrderModifier {
	return func(order *cmacme.Order) {
		order.Annotations = annotations
	}
}

func SetOrderOwnerReference(ref metav1.OwnerReference) OrderModifier {
	return func(order *cmacme.Order) {
		order.OwnerReferences = []metav1.OwnerReference{ref}
	}
}
