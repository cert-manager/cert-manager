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
	s, err := cl.ExtensionsV1beta1().Ingresses(ingress.Namespace).Create(ingress)
	if err != nil {
		if k8sErrors.IsAlreadyExists(err) {
			return cl.ExtensionsV1beta1().Ingresses(ingress.Namespace).Update(ingress)
		}
		return nil, err
	}
	return s, nil
}
