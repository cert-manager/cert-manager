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

package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	networkinglisters "k8s.io/client-go/listers/networking/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	ControllerName = "ingress-shim"
)

type defaults struct {
	autoCertificateAnnotations          []string
	issuerName, issuerKind, issuerGroup string
}

type controller struct {
	kClient  kubernetes.Interface
	cmClient clientset.Interface

	recorder record.EventRecorder
	log      logr.Logger

	ingressLister       networkinglisters.IngressLister
	certificateLister   cmlisters.CertificateLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister

	helper   issuer.Helper
	defaults defaults
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	kShared := ctx.KubeSharedInformerFactory
	cmShared := ctx.SharedInformerFactory

	c.log = logf.FromContext(ctx.RootContext, ControllerName)
	queue := workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName)

	mustSync := []cache.InformerSynced{
		cmShared.Certmanager().V1().Certificates().Informer().HasSynced,
		cmShared.Certmanager().V1().Issuers().Informer().HasSynced,
	}

	c.ingressLister = kShared.Networking().V1beta1().Ingresses().Lister()
	c.certificateLister = cmShared.Certmanager().V1().Certificates().Lister()
	c.issuerLister = cmShared.Certmanager().V1().Issuers().Lister()

	// We don't need to run the ClusterIssuer controller when cert-manager is
	// running in non-namespaced mode (i.e. --namespace="").
	if ctx.Namespace == "" {
		mustSync = append(mustSync, cmShared.Certmanager().V1().ClusterIssuers().Informer().HasSynced)
		c.clusterIssuerLister = cmShared.Certmanager().V1().ClusterIssuers().Lister()
	}

	kShared.Networking().V1beta1().Ingresses().Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{
		Queue: queue,
	})
	cmShared.Certmanager().V1().Certificates().Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificateDeleted(queue),
	})

	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)
	c.kClient = ctx.Client
	c.cmClient = ctx.CMClient
	c.recorder = ctx.Recorder
	c.defaults = defaults{
		ctx.DefaultAutoCertificateAnnotations,
		ctx.DefaultIssuerName,
		ctx.DefaultIssuerKind,
		ctx.DefaultIssuerGroup,
	}

	return queue, mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	crt, err := c.ingressLister.Ingresses(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("ingress '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.sync(ctx, crt)
}

// Whenever a Certificate gets deleted, we want to reconcile its parent Ingress.
// This parent Ingress is called "controller object". For example, the following
// Certificate is controlled by the Ingress "example":
//
//     kind: Certificate
//     metadata:
//       namespace: cert-that-was-deleted
//       ownerReferences:
//       - controller: true                                       ← this
//         apiVersion: networking.k8s.io/v1beta1
//         kind: Ingress
//         name: example
//         blockOwnerDeletion: true
//         uid: 7d3897c2-ce27-4144-883a-e1b5f89bd65a
//
// Note that the owner reference doesn't know about the Ingress's namespace.
func certificateDeleted(queue workqueue.RateLimitingInterface) func(obj interface{}) {
	return func(obj interface{}) {
		cert, ok := obj.(*cmapi.Certificate)
		if !ok {
			runtime.HandleError(fmt.Errorf("not a Certificate object: %#v", obj))
			return
		}

		ingress := metav1.GetControllerOf(cert)
		if ingress == nil {
			// No controller should care about orphans being deleted or
			// updated.
			return
		}

		// We don't check the apiVersion e.g. "networking.k8s.io/v1beta1"
		// because there is no chance that another object called "Ingress" be
		// the controller of a Certificate.
		if ingress.Kind != "Ingress" {
			return
		}

		queue.Add(cert.Namespace + "/" + ingress.Name)
	}
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controller{}).
			Complete()
	})
}
