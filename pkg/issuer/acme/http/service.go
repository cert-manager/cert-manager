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

package http

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// ensureService ensures that a Service exists for the given Challenge. It
// returns the name of the Service and error if any.
func (s *Solver) ensureService(ctx context.Context, ch *cmacme.Challenge) (string, error) {
	log := logf.FromContext(ctx).WithName("ensureService")

	log.V(logf.DebugLevel).Info("checking for existing HTTP01 solver services for challenge")
	existingServices, err := s.getServicesForChallenge(ctx, ch)
	if err != nil {
		return "", err
	}
	if len(existingServices) == 1 {
		logf.WithRelatedResource(log, existingServices[0]).Info("found one existing HTTP01 solver Service for challenge resource")
		return existingServices[0].Name, nil
	}
	if len(existingServices) > 1 {
		log.V(logf.DebugLevel).Info("multiple challenge solver services found for challenge. cleaning up all existing services.")
		err := s.cleanupServices(ctx, ch)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("multiple existing challenge solver services found and cleaned up. retrying challenge sync")
	}

	log.V(logf.DebugLevel).Info("creating HTTP01 challenge solver service")
	svc, err := s.createService(ctx, ch)
	return svc.Name, err
}

// getServicesForChallenge returns a list of services that were created to solve
// http challenges for the given domain
func (s *Solver) getServicesForChallenge(ctx context.Context, ch *cmacme.Challenge) ([]*metav1.PartialObjectMetadata, error) {
	log := logf.FromContext(ctx).WithName("getServicesForChallenge")

	podLabels := podLabels(ch)
	selector := labels.NewSelector()
	for key, val := range podLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{val})
		if err != nil {
			return nil, err
		}
		selector = selector.Add(*req)
	}

	serviceList, err := s.serviceLister.ByNamespace(ch.Namespace).List(selector)
	if err != nil {
		return nil, err
	}

	var relevantServices []*metav1.PartialObjectMetadata
	for _, service := range serviceList {
		s, ok := service.(*metav1.PartialObjectMetadata)
		if !ok {
			return nil, fmt.Errorf("internal error: cannot cast Service PartialObjectMetadata")
		}
		if !metav1.IsControlledBy(s, ch) {
			logf.WithRelatedResource(log, s).Info("found existing solver pod for this challenge resource, however " +
				"it does not have an appropriate OwnerReference referencing this challenge. Skipping it altogether.")
			continue
		}
		relevantServices = append(relevantServices, s)
	}

	return relevantServices, nil
}

// createService will create the service required to solve this challenge
// in the target API server.
func (s *Solver) createService(ctx context.Context, ch *cmacme.Challenge) (*corev1.Service, error) {
	svc, err := buildService(ch)
	if err != nil {
		return nil, err
	}
	return s.Client.CoreV1().Services(ch.Namespace).Create(ctx, svc, metav1.CreateOptions{})
}

func buildService(ch *cmacme.Challenge) (*corev1.Service, error) {
	podLabels := podLabels(ch)
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-acme-http-solver-",
			Namespace:    ch.Namespace,
			Labels:       podLabels,
			Annotations: map[string]string{
				"auth.istio.io/8089": "NONE",
			},
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ch, challengeGvk)},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       acmeSolverListenPort,
					TargetPort: intstr.FromInt32(acmeSolverListenPort),
				},
			},
			Selector: podLabels,
		},
	}

	// checking for presence of http01 config and if set serviceType is set, override our default (NodePort)
	serviceType, err := getServiceType(ch)
	if err != nil {
		return nil, err
	}
	if serviceType != "" {
		service.Spec.Type = serviceType
	}

	return service, nil
}

func (s *Solver) cleanupServices(ctx context.Context, ch *cmacme.Challenge) error {
	log := logf.FromContext(ctx, "cleanupPods")

	services, err := s.getServicesForChallenge(ctx, ch)
	if err != nil {
		return err
	}
	var errs []error
	for _, service := range services {
		log := logf.WithRelatedResource(log, service).V(logf.DebugLevel)
		log.V(logf.DebugLevel).Info("deleting service resource")

		err := s.Client.CoreV1().Services(service.Namespace).Delete(ctx, service.Name, metav1.DeleteOptions{})
		if err != nil {
			log.V(logf.WarnLevel).Info("failed to delete pod resource", "error", err)
			errs = append(errs, err)
			continue
		}
		log.V(logf.DebugLevel).Info("successfully deleted pod resource")
	}
	return utilerrors.NewAggregate(errs)
}
