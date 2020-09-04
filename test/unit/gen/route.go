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
	routev1 "github.com/openshift/api/route/v1"
)

// RouteModifier modifiers for route builder
type RouteModifier func(*routev1.Route)

// Route generate a route with provided modififers
func Route(name string, mods ...RouteModifier) *routev1.Route {
	c := &routev1.Route{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

// AddRouteAnnotations Add the provided annotations to the route
func AddRouteAnnotations(annotations map[string]string) RouteModifier {
	return func(route *routev1.Route) {
		if route.Annotations == nil {
			route.Annotations = make(map[string]string)
		}
		for k, v := range annotations {
			route.Annotations[k] = v
		}
	}
}

// SetRouteNamespace sets the namespace for the route
func SetRouteNamespace(namespace string) RouteModifier {
	return func(crt *routev1.Route) {
		crt.ObjectMeta.Namespace = namespace
	}
}

func SetTLSType(tlsType routev1.TLSTerminationType) RouteModifier {
	return func(route *routev1.Route) {
		if route.Spec.TLS == nil {
			route.Spec.TLS = &routev1.TLSConfig{}
		}

		route.Spec.TLS.Termination = tlsType
	}
}
