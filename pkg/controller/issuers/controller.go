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

package issuers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type Controller struct {
	*controllerpkg.BaseController

	issuerFactory issuer.IssuerFactory

	issuerLister cmlisters.IssuerLister
	secretLister corelisters.SecretLister
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{}
	bctrl := controllerpkg.New(ctx, ControllerName, ctrl.processNextWorkItem)

	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	bctrl.AddQueuing(controllerpkg.DefaultItemBasedRateLimiter(), "issuers", issuerInformer.Informer())
	ctrl.issuerLister = issuerInformer.Lister()

	secretsInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()
	bctrl.AddHandled(secretsInformer.Informer(), &controllerpkg.BlockingEventHandler{WorkFunc: ctrl.secretDeleted})
	ctrl.secretLister = secretsInformer.Lister()

	ctrl.BaseController = bctrl
	ctrl.issuerFactory = issuer.NewIssuerFactory(ctx)

	return ctrl
}

// TODO: replace with generic handleObjet function (like Navigator)
func (c *Controller) secretDeleted(obj interface{}) {
	log := logf.FromContext(c.BaseController.Ctx)

	var secret *corev1.Secret
	var ok bool
	secret, ok = obj.(*corev1.Secret)
	if !ok {
		log.Error(nil, "object was not a secret object")
		return
	}
	log = logf.WithResource(log, secret)
	issuers, err := c.issuersForSecret(secret)
	if err != nil {
		log.Error(err, "error looking up issuers observing secret")
		return
	}
	for _, iss := range issuers {
		key, err := keyFunc(iss)
		if err != nil {
			log.Error(err, "error computing key for resource")
			continue
		}
		c.BaseController.Queue.AddRateLimited(key)
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	issuer, err := c.issuerLister.Issuers(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Error(err, "issuer in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, issuer))
	return c.Sync(ctx, issuer)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "issuers"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return New(ctx).BaseController.Run, nil
	})
}
