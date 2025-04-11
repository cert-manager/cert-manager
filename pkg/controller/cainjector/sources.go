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
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
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
	ReadCA(ctx context.Context, log logr.Logger, metaObj metav1.Object, namespace string) (ca []byte, err error)
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

func (c *kubeconfigDataSource) ReadCA(ctx context.Context, log logr.Logger, metaObj metav1.Object, namespace string) (ca []byte, err error) {
	return c.apiserverCABundle, nil
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

func (c *certificateDataSource) ReadCA(ctx context.Context, log logr.Logger, metaObj metav1.Object, namespace string) (ca []byte, err error) {
	certNameRaw := metaObj.GetAnnotations()[cmapi.WantInjectAnnotation]
	certName := splitNamespacedName(certNameRaw)
	log = log.WithValues("certificate", certName)
	if certName.Namespace == "" {
		err := errors.New("invalid annotation")
		log.Error(err, "invalid certificate name: needs a namespace/ prefix")
		// TODO: should an error be returned here to prevent the caller from proceeding?
		// don't return an error, requeuing won't help till this is changed
		return nil, nil
	}
	if namespace != "" && certName.Namespace != namespace {
		err := fmt.Errorf("cannot read CA data from Certificate in namespace %s, cainjector is scoped to namespace %s", certName.Namespace, namespace)
		forbiddenErr := apierrors.NewForbidden(cmapi.Resource("certificates"), certName.Name, err)
		log.Error(forbiddenErr, "cannot read data source")
		return nil, forbiddenErr
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
	// Only use Secrets that have been created by this Certificate.
	// The Secret must have a `cert-manager.io/certificate-name` annotation
	// value matching the name of this Certificate..
	// NOTE: "owner" is not the `ownerReference`, because cert-manager does not
	// usually set the ownerReference of the Secret.
	// TODO: The logged warning below is misleading because it contains the
	// ownerReference, which is not the reason for ignoring the Secret.
	owner := owningCertForSecret(&secret)
	if owner == nil || *owner != certName {
		log.V(logf.WarnLevel).Info("refusing to target secret not owned by certificate", "owner", metav1.GetControllerOf(&secret))
		return nil, nil
	}

	// inject the CA data
	caData, hasCAData := secret.Data[cmmeta.TLSCAKey]
	if !hasCAData {
		err := errors.New("invalid CA source")
		log.Error(err, "certificate has no CA data")
		// don't requeue, we'll get called when the secret gets updated
		return nil, nil
	}

	return caData, nil
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

func (c *secretDataSource) ReadCA(ctx context.Context, log logr.Logger, metaObj metav1.Object, namespace string) ([]byte, error) {
	secretNameRaw := metaObj.GetAnnotations()[cmapi.WantInjectFromSecretAnnotation]
	secretName := splitNamespacedName(secretNameRaw)
	log = log.WithValues("secret", secretName)
	if secretName.Namespace == "" {
		err := errors.New("invalid annotation")
		log.Error(err, "invalid secret source: missing namespace/ prefix")
		// TODO: should we return error here to prevent the caller from proceeding?
		// don't return an error, requeuing won't help till this is changed
		return nil, nil
	}

	if namespace != "" && secretName.Namespace != namespace {
		err := fmt.Errorf("cannot read CA data from Secret in namespace %s, cainjector is scoped to namespace %s", secretName.Namespace, namespace)
		forbiddenErr := apierrors.NewForbidden(cmapi.Resource("certificates"), secretName.Name, err)
		log.Error(forbiddenErr, "cannot read data source")
		return nil, forbiddenErr
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
		err := errors.New("invalid CA source")
		log.Error(err, "secret contains no CA data")
		// don't requeue, we'll get called when the secret gets updated
		return nil, nil
	}

	return caData, nil
}
