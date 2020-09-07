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

package routes

import (
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const TLSSecret = "kubernetes.io/tls"
const AnnotationBase = "cert-manager.io"
const Cert = "tls.crt"
const Key = "tls.key"
const CA = "ca.crt"
const certAnnotation = AnnotationBase + "/certs-from-secret"
const destCAAnnotation = AnnotationBase + "/destinationCA-from-secret"

func IsRouteResourceAvailable(ctx *controllerpkg.Context) (bool, error) {
	// Query for known OpenShift API resource to verify it is available
	gvk := &schema.GroupVersionKind{
		Group:   "route.openshift.io",
		Version: "v1",
		Kind:    "Route",
	}
	apiResources, err := ctx.RouteClient.Discovery().ServerResourcesForGroupVersion(gvk.GroupVersion().String())

	if err != nil {
		return false, nil
	}
	for _, resource := range apiResources.APIResources {
		if resource.Kind == "Route" {
			return true, nil
		}
	}
	return false, nil
}

var keyFunc = controllerpkg.KeyFunc
