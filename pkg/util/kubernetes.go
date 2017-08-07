package util

import (
	"time"

	batch "k8s.io/api/batch/v1"
	api "k8s.io/api/core/v1"
	core "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	client "github.com/jetstack-experimental/cert-manager/pkg/client"
)

func NewSharedIndexInformerWithLabelsNamespace(client client.Interface, objType runtime.Object, resyncPeriod time.Duration, matchLabels map[string]string, namespace string) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				sel, err := labels.Parse(options.LabelSelector)
				if err != nil {
					return nil, err
				}
				for k, v := range matchLabels {
					req, err := labels.NewRequirement(k, selection.Equals, []string{v})
					if err != nil {
						return nil, err
					}
					sel.Add(*req)
				}
				options.LabelSelector = sel.String()
				return client.CertmanagerV1alpha1().Issuers(namespace).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return client.CertmanagerV1alpha1().Issuers(namespace).Watch(options)
			},
		},
		objType,
		resyncPeriod,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
}

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
