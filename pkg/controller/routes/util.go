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
