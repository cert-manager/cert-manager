/*
Copyright 2026 The cert-manager Authors.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
	gwapix "sigs.k8s.io/gateway-api/apisx/v1alpha1"
	gwlisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
	gwxlisters "sigs.k8s.io/gateway-api/pkg/client/listers/apisx/v1alpha1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	shimhelper "github.com/cert-manager/cert-manager/pkg/controller/certificate-shim"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

const (
	ControllerName       = "listenerset"
	indexByParentGateway = "cert-manager.io/parent-gateway"
)

type controller struct {
	gatewayLister      gwlisters.GatewayLister
	xlistenerSetLister gwxlisters.XListenerSetLister

	sync shimhelper.SyncFn

	// For testing purposes.
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName]
}

func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	c.gatewayLister = ctx.GWShared.Gateway().V1().Gateways().Lister()
	c.xlistenerSetLister = ctx.GWShared.Experimental().V1alpha1().XListenerSets().Lister()
	log := logf.FromContext(ctx.RootContext, ControllerName)

	c.sync = shimhelper.SyncFnFor(ctx.Recorder, log, ctx.CMClient, ctx.SharedInformerFactory.Certmanager().V1().Certificates().Lister(), ctx.IngressShimOptions, ctx.FieldManager)

	xlsInf := ctx.GWShared.Experimental().V1alpha1().XListenerSets().Informer()

	// Adding an indexer for easier queries on xlistenerset
	if err := xlsInf.AddIndexers(cache.Indexers{
		indexByParentGateway: func(obj any) ([]string, error) {
			xls, ok := obj.(*gwapix.XListenerSet)
			if !ok {
				return nil, nil
			}

			ns := xls.GetNamespace()
			if xls.Spec.ParentRef.Namespace != nil && string(*xls.Spec.ParentRef.Namespace) != "" {
				ns = string(*xls.Spec.ParentRef.Namespace)
			}
			if xls.Spec.ParentRef.Name == "" {
				return nil, nil
			}

			return []string{fmt.Sprintf("%s/%s", ns, xls.Spec.ParentRef.Name)}, nil
		},
	}); err != nil {
		return nil, nil, fmt.Errorf("error adding indexer for xlistenerset %v", err)
	}

	if _, err := xlsInf.AddEventHandler(controllerpkg.QueuingEventHandler(c.queue)); err != nil {
		return nil, nil, fmt.Errorf("error setting up event handler for xlistenerset %v", err)
	}

	// we need to reconcile xlistenersets when gateways change
	if _, err := ctx.GWShared.Gateway().V1().Gateways().Informer().AddEventHandler(controllerpkg.BlockingEventHandler(func(gw *gwapi.Gateway) {
		key := fmt.Sprintf("%s/%s", gw.Namespace, gw.Name)

		indexed, err := xlsInf.GetIndexer().ByIndex(indexByParentGateway, key)
		if err != nil {
			runtime.HandleError(fmt.Errorf("cannot get object for index %v", err))
			return
		}

		for _, in := range indexed {
			ls, ok := in.(*gwapix.XListenerSet)
			if !ok {
				continue
			}

			c.queue.Add(types.NamespacedName{Name: ls.Name, Namespace: ls.Namespace})
		}
	})); err != nil {
		return nil, nil, fmt.Errorf("error setting up event handler for gateway %v", err)
	}

	// Requeue parent XListenerSet when a Certificate is added/updated/deleted,
	// mirroring the existing gateway-shim behavior
	if _, err := ctx.SharedInformerFactory.Certmanager().V1().Certificates().Informer().AddEventHandler(
		controllerpkg.BlockingEventHandler(xListenerSetCertificateHandler(c.queue)),
	); err != nil {
		return nil, nil, fmt.Errorf("error setting up certificate handler: %v", err)
	}

	mustSync := []cache.InformerSynced{
		ctx.GWShared.Gateway().V1().Gateways().Informer().HasSynced,
		ctx.GWShared.Experimental().V1alpha1().XListenerSets().Informer().HasSynced,
		ctx.SharedInformerFactory.Certmanager().V1().Certificates().Informer().HasSynced,
	}

	return c.queue, mustSync, nil
}

func (c *controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	xls, err := c.xlistenerSetLister.XListenerSets(key.Namespace).Get(key.Name)
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}

	if xls == nil || xls.DeletionTimestamp != nil {
		return nil
	}

	parentNS := xls.Namespace
	if xls.Spec.ParentRef.Namespace != nil && string(*xls.Spec.ParentRef.Namespace) != "" {
		parentNS = string(*xls.Spec.ParentRef.Namespace)
	}

	parentName := string(xls.Spec.ParentRef.Name)
	if parentName == "" {
		return nil
	}

	gw, err := c.gatewayLister.Gateways(parentNS).Get(parentName)
	if err != nil && !k8sErrors.IsNotFound(err) {
		return err
	}

	if gw == nil || gw.DeletionTimestamp != nil {
		return nil
	}

	toSyncXLS := xls.DeepCopy()
	inheritAnnotations(toSyncXLS, gw)

	return c.sync(ctx, toSyncXLS)
}

func inheritAnnotations(xls *gwapix.XListenerSet, gw *gwapi.Gateway) {
	xlsAnn := xls.GetAnnotations()
	if xlsAnn == nil {
		xlsAnn = map[string]string{}
	}

	gwAnn := gw.GetAnnotations()
	if gwAnn == nil {
		return
	}

	_, hasClusterIssuer := xlsAnn[cmapi.IngressClusterIssuerNameAnnotationKey]
	_, hasIssuer := xlsAnn[cmapi.IngressIssuerNameAnnotationKey]

	if !hasClusterIssuer && !hasIssuer {
		if v, ok := gwAnn[cmapi.IngressClusterIssuerNameAnnotationKey]; ok {
			xlsAnn[cmapi.IngressClusterIssuerNameAnnotationKey] = v
		}

		if v, ok := gwAnn[cmapi.IngressIssuerNameAnnotationKey]; ok {
			xlsAnn[cmapi.IngressIssuerNameAnnotationKey] = v
		}
	}

	if v, ok := gwAnn[cmapi.IssuerKindAnnotationKey]; ok {
		xlsAnn[cmapi.IssuerKindAnnotationKey] = v
	}

	if v, ok := gwAnn[cmapi.IssuerGroupAnnotationKey]; ok {
		xlsAnn[cmapi.IssuerGroupAnnotationKey] = v
	}

	xls.SetAnnotations(xlsAnn)
}

func xListenerSetCertificateHandler(queue workqueue.TypedRateLimitingInterface[types.NamespacedName]) func(crt *cmapi.Certificate) {
	return func(crt *cmapi.Certificate) {
		ref := metav1.GetControllerOf(crt)
		if ref == nil {
			// No controller should care about orphans being deleted or
			// updated.
			return
		}

		if ref.Kind != "XListenerSet" {
			return
		}

		queue.Add(types.NamespacedName{
			Namespace: crt.Namespace,
			Name:      ref.Name,
		})
	}
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controller{queue: workqueue.NewTypedRateLimitingQueueWithConfig(
				controllerpkg.DefaultItemBasedRateLimiter(),
				workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
					Name: ControllerName,
				},
			)}).
			Complete()
	})
}
