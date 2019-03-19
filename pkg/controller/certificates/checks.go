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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

func (c *Controller) handleGenericIssuer(obj interface{}) {
	log := logf.FromContext(c.ctx, "handleGenericIssuer")

	iss, ok := obj.(cmapi.GenericIssuer)
	if !ok {
		log.Error(nil, "object does not implement GenericIssuer")
		return
	}

	log = logf.WithResource(log, iss)
	certs, err := c.certificatesForGenericIssuer(iss)
	if err != nil {
		log.Error(err, "error looking up certificates observing issuer or clusterissuer")
		return
	}
	for _, crt := range certs {
		log := logf.WithRelatedResource(log, crt)
		key, err := keyFunc(crt)
		if err != nil {
			log.Error(err, "error computing key for resource")
			continue
		}
		c.queue.Add(key)
	}
}

func (c *Controller) handleSecretResource(obj interface{}) {
	log := logf.FromContext(c.ctx, "handleSecretResource")

	secret, ok := obj.(*corev1.Secret)
	if !ok {
		log.Error(nil, "object is not a Secret resource")
		return
	}
	log = logf.WithResource(log, secret)

	crts, err := c.certificatesForSecret(secret)
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
		c.queue.Add(key)
	}
}

func (c *Controller) certificatesForSecret(secret *corev1.Secret) ([]*cmapi.Certificate, error) {
	crts, err := c.certificateLister.List(labels.NewSelector())

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

func (c *Controller) certificatesForGenericIssuer(iss cmapi.GenericIssuer) ([]*cmapi.Certificate, error) {
	crts, err := c.certificateLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificiates: %s", err.Error())
	}

	_, isClusterIssuer := iss.(*cmapi.ClusterIssuer)

	var affected []*cmapi.Certificate
	for _, crt := range crts {
		if isClusterIssuer && crt.Spec.IssuerRef.Kind != cmapi.ClusterIssuerKind {
			continue
		}
		if !isClusterIssuer {
			if crt.Namespace != iss.GetObjectMeta().Namespace {
				continue
			}
		}
		if crt.Spec.IssuerRef.Name != iss.GetObjectMeta().Name {
			continue
		}
		affected = append(affected, crt)
	}

	return affected, nil
}

func (c *Controller) handleOwnedResource(obj interface{}) {
	log := logf.FromContext(c.ctx, "handleOwnedResource")

	metaobj, ok := obj.(metav1.Object)
	if !ok {
		log.Error(nil, "item passed to handleOwnedResource does not implement ObjectMetaAccessor")
		return
	}

	log = logf.WithResource(log, metaobj)
	log.V(logf.DebugLevel).Info("looking up owners for resource")

	ownerRefs := metaobj.GetOwnerReferences()
	for _, ref := range ownerRefs {
		log := log.WithValues(
			logf.RelatedResourceNamespaceKey, metaobj.GetNamespace(),
			logf.RelatedResourceNameKey, ref.Name,
			logf.RelatedResourceKindKey, ref.Kind,
		)
		log.V(logf.DebugLevel).Info("evaluating ownerRef on resource")

		// Parse the Group out of the OwnerReference to compare it to what was parsed out of the requested OwnerType
		refGV, err := schema.ParseGroupVersion(ref.APIVersion)
		if err != nil {
			log.Error(err, "could not parse ownerReference GroupVersion")
			continue
		}

		if refGV.Group == certificateGvk.Group && ref.Kind == certificateGvk.Kind {
			// TODO: how to handle namespace of owner references?
			cert, err := c.certificateLister.Certificates(metaobj.GetNamespace()).Get(ref.Name)
			if err != nil {
				log.Error(err, "error getting owning certificate resource")
				continue
			}
			objKey, err := keyFunc(cert)
			if err != nil {
				log.Error(err, "error computing key for resource")
				continue
			}
			c.queue.Add(objKey)
		}
	}
}
