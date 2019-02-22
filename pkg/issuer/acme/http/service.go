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

package http

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/klog"
)

func (s *Solver) ensureService(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (*corev1.Service, error) {
	existingServices, err := s.getServicesForChallenge(ch)
	if err != nil {
		return nil, err
	}
	if len(existingServices) == 1 {
		return existingServices[0], nil
	}
	if len(existingServices) > 1 {
		errMsg := fmt.Sprintf("multiple challenge solver services found for certificate '%s/%s'. Cleaning up existing services.", ch.Namespace, ch.Name)
		klog.Infof(errMsg)
		err := s.cleanupServices(ch)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(errMsg)
	}

	klog.Infof("No existing HTTP01 challenge solver service found for Certificate %q. One will be created.", ch.Namespace+"/"+ch.Name)
	return s.createService(issuer, ch)
}

// getServicesForChallenge returns a list of services that were created to solve
// http challenges for the given domain
func (s *Solver) getServicesForChallenge(ch *v1alpha1.Challenge) ([]*corev1.Service, error) {
	podLabels := podLabels(ch)
	selector := labels.NewSelector()
	for key, val := range podLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{val})
		if err != nil {
			return nil, err
		}
		selector = selector.Add(*req)
	}

	serviceList, err := s.serviceLister.Services(ch.Namespace).List(selector)
	if err != nil {
		return nil, err
	}

	var relevantServices []*corev1.Service
	for _, service := range serviceList {
		if !metav1.IsControlledBy(service, ch) {
			klog.Infof("Found service %q with acme-order-url annotation set to that of Certificate %q"+
				"but it is not owned by the Certificate resource, so skipping it.", service.Namespace+"/"+service.Name, ch.Namespace+"/"+ch.Name)
			continue
		}
		relevantServices = append(relevantServices, service)
	}

	return relevantServices, nil
}

// createService will create the service required to solve this challenge
// in the target API server.
func (s *Solver) createService(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (*corev1.Service, error) {
	return s.Client.CoreV1().Services(ch.Namespace).Create(buildService(issuer, ch))
}

func buildService(issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) *corev1.Service {
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
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       acmeSolverListenPort,
					TargetPort: intstr.FromInt(acmeSolverListenPort),
				},
			},
			Selector: podLabels,
		},
	}

	// checking for presence of http01 config and if set serviceType is set, override our default (NodePort)
	service.Spec.Type = corev1.ServiceTypeNodePort
	if issuer.GetSpec().ACME.HTTP01 != nil && issuer.GetSpec().ACME.HTTP01.ServiceType != "" {
		service.Spec.Type = issuer.GetSpec().ACME.HTTP01.ServiceType
	}

	return service
}

func (s *Solver) cleanupServices(ch *v1alpha1.Challenge) error {
	services, err := s.getServicesForChallenge(ch)
	if err != nil {
		return err
	}
	var errs []error
	for _, service := range services {
		// TODO: should we call DeleteCollection here? We'd need to somehow
		// also ensure ownership as part of that request using a FieldSelector.
		err := s.Client.CoreV1().Services(service.Namespace).Delete(service.Name, nil)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs)
}
