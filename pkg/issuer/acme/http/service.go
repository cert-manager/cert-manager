package http

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (s *Solver) ensureService(crt *v1alpha1.Certificate, domain, token, key string) (*corev1.Service, error) {
	existingServices, err := s.getServicesForCertificate(crt, domain)
	if err != nil {
		return nil, err
	}
	var service *corev1.Service
	if len(existingServices) > 1 {
		errMsg := fmt.Sprintf("multiple challenge solver services found for certificate '%s/%s'. Cleaning up existing services.", crt.Namespace, crt.Name)
		glog.Infof(errMsg)
		err := s.cleanupServices(crt, domain)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(errMsg)
	}
	if len(existingServices) == 0 {
		glog.Infof("No existing HTTP01 challenge solver service found for Certificate %q. One will be created.")
		service, err = s.createService(crt, domain)
		if err != nil {
			return nil, err
		}
	}
	return service, nil
}

// getServicesForCertificate returns a list of services that were created to solve
// http challenges for the given domain
func (s *Solver) getServicesForCertificate(crt *v1alpha1.Certificate, domain string) ([]*corev1.Service, error) {
	if crt.Status.ACME.Order.URL == "" {
		return []*corev1.Service{}, nil
	}
	podLabels := podLabels(crt, domain)
	selector := labels.NewSelector()
	for key, val := range podLabels {
		req, err := labels.NewRequirement(key, selection.Equals, []string{val})
		if err != nil {
			return nil, err
		}
		selector = selector.Add(*req)
	}

	serviceList, err := s.serviceLister.Services(crt.Namespace).List(selector)
	if err != nil {
		return nil, err
	}

	var relevantServices []*corev1.Service
	for _, service := range serviceList {
		if !metav1.IsControlledBy(service, crt) {
			glog.Infof("Found service %q with acme-order-url annotation set to that of Certificate %q"+
				"but it is not owned by the Certificate resource, so skipping it.", service.Name, crt.Name)
			continue
		}
		relevantServices = append(relevantServices, service)
	}

	return relevantServices, nil
}

// createService will create the service required to solve this challenge
// in the target API server.
func (s *Solver) createService(crt *v1alpha1.Certificate, domain string) (*corev1.Service, error) {
	podLabels := podLabels(crt, domain)
	return s.client.CoreV1().Services(crt.Namespace).Create(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "cm-acme-http-solver-",
			Namespace:       crt.Namespace,
			Labels:          podLabels,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       acmeSolverListenPort,
					TargetPort: intstr.FromInt(acmeSolverListenPort),
				},
			},
			Selector: podLabels,
		},
	})
}

func (s *Solver) cleanupServices(crt *v1alpha1.Certificate, domain string) error {
	services, err := s.getServicesForCertificate(crt, domain)
	if err != nil {
		return err
	}
	var errs []error
	for _, service := range services {
		// TODO: should we call DeleteCollection here? We'd need to somehow
		// also ensure ownership as part of that request using a FieldSelector.
		err := s.client.CoreV1().Services(service.Namespace).Delete(service.Name, nil)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs)
}
