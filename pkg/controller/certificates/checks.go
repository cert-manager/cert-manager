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

package certificates

import (
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

func secretResourceHandler(log logr.Logger, certificateLister cmlisters.CertificateLister, queue workqueue.Interface) func(obj interface{}) {
	return func(obj interface{}) {
		log := log.WithName("handleSecretResource")

		secret, ok := obj.(*corev1.Secret)
		if !ok {
			log.Error(nil, "object is not a Secret resource")
			return
		}
		log = logf.WithResource(log, secret)

		crts, err := certificatesForSecret(certificateLister, secret)
		if err != nil {
			log.Error(err, "error looking up Certificates observing Secret")
			return
		}
		for _, crt := range crts {
			log := logf.WithRelatedResource(log, crt)
			key, err := keyFunc(crt)
			if err != nil {
				log.Error(err, "error computing key for resource")
				continue
			}
			queue.Add(key)
		}
	}
}

func certificatesForSecret(certificateLister cmlisters.CertificateLister, secret *corev1.Secret) ([]*cmapi.Certificate, error) {
	crts, err := certificateLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	var affected []*cmapi.Certificate
	for _, crt := range crts {
		if crt.Namespace != secret.Namespace {
			continue
		}
		if crt.Spec.SecretName == secret.Name {
			affected = append(affected, crt)
		}
	}

	return affected, nil
}
