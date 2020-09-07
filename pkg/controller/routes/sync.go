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
	"context"

	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	logf "github.com/jetstack/cert-manager/pkg/logs"
)

func (c *routeRequestManager) Sync(ctx context.Context, instance *routev1.Route) (err error) {
	log := logf.FromContext(ctx)

	log.Info("Reconciling Route", "route", instance)

	if instance.Spec.TLS == nil {
		return nil
	}
	secretName, ok := instance.GetAnnotations()[certAnnotation]
	caSecretName, okCa := instance.GetAnnotations()[destCAAnnotation]
	shouldUpdate := false

	if !ok {
		log.Error(nil, "Unable to get annotation", "route", instance)
		if instance.Spec.TLS.Key != "" {
			instance.Spec.TLS.Key = ""
			shouldUpdate = true
		}
		if instance.Spec.TLS.Certificate != "" {
			instance.Spec.TLS.Certificate = ""
			shouldUpdate = true
		}
		if instance.Spec.TLS.CACertificate != "" {
			instance.Spec.TLS.CACertificate = ""
			shouldUpdate = true
		}

	} else {
		log.Info("found secret", "secret", secretName)
		secret, err := c.secretLister.Secrets(instance.GetNamespace()).Get(secretName)
		if err != nil {
			log.Error(err, "unable to find referenced secret", "secret", secretName)
			return err
		}
		log.Info("Attaching Cert to Route from Secret", "secret", secretName)
		shouldUpdate = shouldUpdate || populateRouteWithCertifcates(instance, secret)
	}
	if !okCa {
		if instance.Spec.TLS.DestinationCACertificate != "" {
			instance.Spec.TLS.DestinationCACertificate = ""
			shouldUpdate = true
		}
	} else {
		secret, err := c.secretLister.Secrets(instance.GetNamespace()).Get(caSecretName)
		if err != nil {
			log.Error(err, "unable to find referenced ca secret", "secret", secretName)
			return err
		}
		shouldUpdate = shouldUpdate || populateRouteDestCA(instance, secret)
	}

	if shouldUpdate {
		_, err = c.routeClient.RouteV1().Routes(instance.GetNamespace()).Update(context.TODO(), instance, metav1.UpdateOptions{})
		if err != nil {
			log.Error(err, "unable to update route", "route", instance)
			return err
		}
	}

	return nil
}

func populateRouteWithCertifcates(route *routev1.Route, secret *corev1.Secret) bool {
	shouldUpdate := false
	if route.Spec.TLS.Termination == "edge" || route.Spec.TLS.Termination == "reencrypt" {
		// here we need to replace the terminating certifciate
		if value, ok := secret.Data[Key]; ok && len(value) != 0 {
			if route.Spec.TLS.Key != string(value) {
				route.Spec.TLS.Key = string(value)
				shouldUpdate = true
			}
		}
		if value, ok := secret.Data[Cert]; ok && len(value) != 0 {
			if route.Spec.TLS.Certificate != string(value) {
				route.Spec.TLS.Certificate = string(value)
				shouldUpdate = true
			}
		}
		if value, ok := secret.Data[CA]; ok && len(value) != 0 {
			if route.Spec.TLS.CACertificate != string(value) {
				route.Spec.TLS.CACertificate = string(value)
				shouldUpdate = true
			}
		}
	}
	return shouldUpdate
}

func populateRouteDestCA(route *routev1.Route, secret *corev1.Secret) bool {
	shouldUpdate := false
	if value, ok := secret.Data[CA]; ok && len(value) != 0 {
		if route.Spec.TLS.DestinationCACertificate != string(value) {
			route.Spec.TLS.DestinationCACertificate = string(value)
			shouldUpdate = true
		}
	}
	return shouldUpdate
}
