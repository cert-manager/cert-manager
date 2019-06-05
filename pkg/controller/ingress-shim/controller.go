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

package controller

import (
	"context"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	extlisters "k8s.io/client-go/listers/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	cmv1alpha1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

const (
	ControllerName = "ingress-shim"
)

type defaults struct {
	autoCertificateAnnotations  []string
	issuerName, issuerKind      string
	acmeIssuerChallengeType     string
	acmeIssuerDNS01ProviderName string
}

type Controller struct {
	*controllerpkg.BaseController

	Client   kubernetes.Interface
	CMClient clientset.Interface
	Recorder record.EventRecorder

	helper issuer.Helper

	ingressLister       extlisters.IngressLister
	certificateLister   cmlisters.CertificateLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister

	defaults defaults
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{
		Client:   ctx.Client,
		CMClient: ctx.CMClient,
		Recorder: ctx.Recorder,
		defaults: defaults{
			ctx.DefaultAutoCertificateAnnotations,
			ctx.DefaultIssuerName,
			ctx.DefaultIssuerKind,
			ctx.DefaultACMEIssuerChallengeType,
			ctx.DefaultACMEIssuerDNS01ProviderName,
		},
	}
	bctrl := controllerpkg.New(ctx, ControllerName, ctrl.processNextWorkItem)

	ingressInformer := ctx.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses()
	bctrl.AddQueuing(controllerpkg.DefaultItemBasedRateLimiter(), "ingresses", ingressInformer.Informer())
	ctrl.ingressLister = ingressInformer.Lister()

	certificatesInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Certificates()
	bctrl.AddHandled(certificatesInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.certificateDeleted})
	ctrl.certificateLister = certificatesInformer.Lister()

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	bctrl.AddWatched(issuerInformer.Informer())
	ctrl.issuerLister = issuerInformer.Lister()

	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		bctrl.AddWatched(clusterIssuerInformer.Informer())
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	ctrl.BaseController = bctrl
	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)

	return ctrl
}

func (c *Controller) certificateDeleted(obj interface{}) {
	crt, ok := obj.(*cmv1alpha1.Certificate)
	if !ok {
		runtime.HandleError(fmt.Errorf("Object is not a certificate object %#v", obj))
		return
	}
	ings, err := c.ingressesForCertificate(crt)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error looking up ingress observing certificate: %s/%s", crt.Namespace, crt.Name))
		return
	}
	for _, crt := range ings {
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(crt)
		if err != nil {
			runtime.HandleError(err)
			continue
		}
		c.BaseController.Queue.Add(key)
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
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

	return c.Sync(ctx, crt)
}

var keyFunc = controllerpkg.KeyFunc

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return New(ctx).BaseController.Run, nil
	})
}
