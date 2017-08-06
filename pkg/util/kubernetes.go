package util

import (
	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

func EnsureSecret(cl kubernetes.Interface, secret *api.Secret) (*api.Secret, error) {
	s, err := cl.CoreV1().Secrets(secret.Namespace).Create(secret)
	if err != nil {
		if k8sErrors.IsAlreadyExists(err) {
			return cl.CoreV1().Secrets(secret.Namespace).Update(secret)
		}
		return nil, err
	}
	return s, nil
}

func EnsureIngress(cl kubernetes.Interface, ingress *extensions.Ingress) (*extensions.Ingress, error) {
	s, err := cl.ExtensionsV1beta1().Ingresses(ingress.Namespace).Update(ingress)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			return cl.ExtensionsV1beta1().Ingresses(ingress.Namespace).Create(ingress)
		}
		return nil, err
	}
	return s, nil
}

func EnsureService(cl kubernetes.Interface, service *core.Service) (*core.Service, error) {
	s, err := cl.CoreV1().Services(service.Namespace).Update(service)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			return cl.CoreV1().Services(service.Namespace).Create(service)
		}
		return nil, err
	}
	return s, nil
}

func EnsureJob(cl kubernetes.Interface, job *batch.Job) (*batch.Job, error) {
	s, err := cl.BatchV1().Jobs(job.Namespace).Update(job)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			return cl.BatchV1().Jobs(job.Namespace).Create(job)
		}
		return nil, err
	}
	return s, nil
}
