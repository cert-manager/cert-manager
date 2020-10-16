package routes

import (
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/workqueue"

	logf "github.com/jetstack/cert-manager/pkg/logs"
	routev1 "github.com/openshift/api/route/v1"
	routeListers "github.com/openshift/client-go/route/listers/route/v1"
)

func secretResourceHandler(log logr.Logger, routeLister routeListers.RouteLister, queue workqueue.Interface) func(obj interface{}) {
	return func(obj interface{}) {
		log := log.WithName("handleSecretResource")

		secret, ok := obj.(*corev1.Secret)
		if !ok {
			log.Error(nil, "object is not a Secret resource")
			return
		}
		log = logf.WithResource(log, secret)

		routes, err := routesForSecret(routeLister, secret)
		if err != nil {
			log.Error(err, "error looking up Certificates observing Secret")
			return
		}
		for _, route := range routes {
			log := logf.WithRelatedResource(log, route)
			key, err := keyFunc(route)
			if err != nil {
				log.Error(err, "error computing key for resource")
				continue
			}
			queue.Add(key)
		}
	}
}

func routesForSecret(routeLister routeListers.RouteLister, secret *corev1.Secret) ([]*routev1.Route, error) {
	routes, err := routeLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing routes: %s", err.Error())
	}

	var affected []*routev1.Route
	for _, route := range routes {
		if route.Namespace != secret.Namespace {
			continue
		}
		if route.GetAnnotations()[certAnnotation] == secret.Name {
			affected = append(affected, route)
		}
		if route.GetAnnotations()[destCAAnnotation] == secret.Name {
			affected = append(affected, route)
		}
	}

	return affected, nil
}
