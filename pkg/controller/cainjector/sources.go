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

package cainjector

import (
	"context"

	logf "github.com/cert-manager/cert-manager/pkg/logs"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

// caDataSource knows how to extract CA data given a provided InjectTarget.
// This allows adaptable implementations of fetching CA data based on
// configuration given on the injection target (e.g. annotations).

type caDataSource interface {
	// Configured returns true if this data source should be used for the given
	// InjectTarget, i.e. if it has appropriate annotations enabled to use the
	// annotations.
	Configured(log logr.Logger, metaObj metav1.Object) bool

	// ReadCA reads the CA that should be injected into the InjectTarget based
	// on the configuration provided in the InjectTarget.
	// ReadCA may return nil, nil if the CA data cannot be read.
	// In this case, the caller should not retry the operation.
	// It is up to the ReadCA implementation to inform the user why the CA
	// failed to read.
	ReadCA(ctx context.Context, log logr.Logger, metaObj metav1.Object) (ca []byte, err error)

	// ApplyTo applies any required watchers to the given controller.
	ApplyTo(ctx context.Context, mgr ctrl.Manager, setup injectorSetup, controller controller.Controller, ca cache.Cache) error
}

// kubeconfigDataSource reads the ca bundle provided as part of the struct
// instantiation if it has the 'cert-manager.io/inject-apiserver-ca'
// annotation.
type kubeconfigDataSource struct {
	apiserverCABundle []byte
}

func (c *kubeconfigDataSource) Configured(log logr.Logger, metaObj metav1.Object) bool {
	return metaObj.GetAnnotations()[cmapi.WantInjectAPIServerCAAnnotation] == "true"
}

func (c *kubeconfigDataSource) ReadCA(ctx context.Context, log logr.Logger, metaObj metav1.Object) (ca []byte, err error) {
	return c.apiserverCABundle, nil
}

func (c *kubeconfigDataSource) ApplyTo(ctx context.Context, mgr ctrl.Manager, setup injectorSetup, _ controller.Controller, _ cache.Cache) error {
	cfg := mgr.GetConfig()
	caBundle, err := dataFromSliceOrFile(cfg.CAData, cfg.CAFile)
	if err != nil {
		return err
	}
	c.apiserverCABundle = caBundle
	return nil
}

// certificateDataSource reads a CA bundle by fetching the Certificate named in
// the 'cert-manager.io/inject-ca-from' annotation in the form
// 'namespace/name'.
type certificateDataSource struct {
	client client.Reader
}

func (c *certificateDataSource) Configured(log logr.Logger, metaObj metav1.Object) bool {
	certNameRaw, ok := metaObj.GetAnnotations()[cmapi.WantInjectAnnotation]
	if !ok {
		return false
	}
	log.V(logf.DebugLevel).Info("Extracting CA from Certificate resource", "certificate", certNameRaw)
	return true
}

func (c *certificateDataSource) ReadCA(ctx context.Context, log logr.Logger, metaObj metav1.Object) (ca []byte, err error) {
	certNameRaw := metaObj.GetAnnotations()[cmapi.WantInjectAnnotation]
	certName := splitNamespacedName(certNameRaw)
	log = log.WithValues("certificate", certName)
	if certName.Namespace == "" {
		log.Error(nil, "invalid certificate name; needs a namespace/ prefix")
		// don't return an error, requeuing won't help till this is changed
		return nil, nil
	}

	var cert cmapi.Certificate
	if err := c.client.Get(ctx, certName, &cert); err != nil {
		log.Error(err, "unable to fetch associated certificate")
		// don't requeue if we're just not found, we'll get called when the secret gets created
		return nil, dropNotFound(err)
	}

	secretName := &types.NamespacedName{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
	// grab the associated secret, and ensure it's owned by the cert
	log = log.WithValues("secret", secretName)
	var secret corev1.Secret
	if err := c.client.Get(ctx, *secretName, &secret); err != nil {
		log.Error(err, "unable to fetch associated secret")
		// don't requeue if we're just not found, we'll get called when the secret gets created
		return nil, dropNotFound(err)
	}
	owner := OwningCertForSecret(&secret)
	if owner == nil || *owner != certName {
		log.V(logf.WarnLevel).Info("refusing to target secret not owned by certificate", "owner", metav1.GetControllerOf(&secret))
		return nil, nil
	}

	// inject the CA data
	caData, hasCAData := secret.Data[cmmeta.TLSCAKey]
	if !hasCAData {
		log.Error(nil, "certificate has no CA data")
		// don't requeue, we'll get called when the secret gets updated
		return nil, nil
	}

	return caData, nil
}

func (c *certificateDataSource) ApplyTo(ctx context.Context, mgr ctrl.Manager, setup injectorSetup, controller controller.Controller, ca cache.Cache) error {
	typ := setup.injector.NewTarget().AsObject()
	if err := ca.IndexField(ctx, typ, injectFromPath, injectableCAFromIndexer); err != nil {
		return err
	}

	if err := controller.Watch(source.NewKindWithCache(&cmapi.Certificate{}, ca),
		handler.EnqueueRequestsFromMapFunc((&certMapper{
			Client:       ca,
			log:          ctrl.Log.WithName("cert-mapper"),
			toInjectable: buildCertToInjectableFunc(setup.listType, setup.resourceName),
		}).Map),
	); err != nil {
		return err
	}
	if err := controller.Watch(source.NewKindWithCache(&corev1.Secret{}, ca),
		handler.EnqueueRequestsFromMapFunc((&secretForCertificateMapper{
			Client:                  ca,
			log:                     ctrl.Log.WithName("secret-for-certificate-mapper"),
			certificateToInjectable: buildCertToInjectableFunc(setup.listType, setup.resourceName),
		}).Map),
	); err != nil {
		return err
	}
	return nil
}

// secretDataSource reads a CA bundle from a Secret resource named using the
// 'cert-manager.io/inject-ca-from-secret' annotation in the form
// 'namespace/name'.
type secretDataSource struct {
	client client.Reader
}

func (c *secretDataSource) Configured(log logr.Logger, metaObj metav1.Object) bool {
	secretNameRaw, ok := metaObj.GetAnnotations()[cmapi.WantInjectFromSecretAnnotation]
	if !ok {
		return false
	}
	log.V(logf.DebugLevel).Info("Extracting CA from Secret resource", "secret", secretNameRaw)
	return true
}

func (c *secretDataSource) ReadCA(ctx context.Context, log logr.Logger, metaObj metav1.Object) ([]byte, error) {
	secretNameRaw := metaObj.GetAnnotations()[cmapi.WantInjectFromSecretAnnotation]
	secretName := splitNamespacedName(secretNameRaw)
	log = log.WithValues("secret", secretName)
	if secretName.Namespace == "" {
		log.Error(nil, "invalid certificate name")
		// don't return an error, requeuing won't help till this is changed
		return nil, nil
	}

	// grab the associated secret
	var secret corev1.Secret
	if err := c.client.Get(ctx, secretName, &secret); err != nil {
		log.Error(err, "unable to fetch associated secret")
		// don't requeue if we're just not found, we'll get called when the secret gets created
		return nil, dropNotFound(err)
	}

	if secret.Annotations == nil || secret.Annotations[cmapi.AllowsInjectionFromSecretAnnotation] != "true" {
		log.V(logf.WarnLevel).Info("Secret resource does not allow direct injection - refusing to inject CA")
		return nil, nil
	}

	// inject the CA data
	caData, hasCAData := secret.Data[cmmeta.TLSCAKey]
	if !hasCAData {
		log.Error(nil, "certificate has no CA data")
		// don't requeue, we'll get called when the secret gets updated
		return nil, nil
	}

	return caData, nil
}

func (c *secretDataSource) ApplyTo(ctx context.Context, mgr ctrl.Manager, setup injectorSetup, controller controller.Controller, ca cache.Cache) error {
	typ := setup.injector.NewTarget().AsObject()
	if err := ca.IndexField(ctx, typ, injectFromSecretPath, injectableCAFromSecretIndexer); err != nil {
		return err
	}
	if err := controller.Watch(source.NewKindWithCache(&corev1.Secret{}, ca),
		handler.EnqueueRequestsFromMapFunc((&secretForInjectableMapper{
			Client:             ca,
			log:                ctrl.Log.WithName("secret-mapper"),
			secretToInjectable: buildSecretToInjectableFunc(setup.listType, setup.resourceName),
		}).Map),
	); err != nil {
		return err
	}
	return nil
}
