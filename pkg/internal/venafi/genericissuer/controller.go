/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package genericissuer

import (
	"context"
	"errors"
	"fmt"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	venaficlient "github.com/jetstack/cert-manager/pkg/internal/venafi/client"
	venafidefaults "github.com/jetstack/cert-manager/pkg/internal/venafi/defaults"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	ControllerNameIssuer        = "venafi-issuer"
	ControllerNameClusterIssuer = "venafi-clusterissuer"

	// ProcessItem will be re-executed after this delay if it finds a
	// matching Venafi configured issuer and if it exits without error.
	// If it exits with an error, the parent controller will handle retries,
	// with backoff.
	recheckDelay = time.Minute * 1

	baseDelay = time.Second * 1
	maxDelay  = time.Second * 30
)

// issuerGetter is used by the controller to get a GenericIssuer with the given namespace and name.
// It is injected into the generic controller to allow it to handle both ClusterIssuer and Issuer.
// It also allows this operation to be stubbed out in unit tests so that errors can be simulated.
type issuerGetter func(ctx context.Context, namespace, name string) (cmapi.GenericIssuer, error)

// issuerGetterFromIssuerLister returns an issuerGetter that gets Issuer
// resources from the supplied lister
func issuerGetterFromIssuerLister(issuerLister cmlisters.IssuerLister) issuerGetter {
	return func(ctx context.Context, namespace, name string) (cmapi.GenericIssuer, error) {
		issuer, err := issuerLister.Issuers(namespace).Get(name)
		if err != nil {
			return nil, err
		}
		issuer = issuer.DeepCopy()
		venafidefaults.SetDefaults_Issuer(issuer)
		return issuer, nil
	}
}

// issuerGetterFromClusterIssuerLister returns an issuerGetter that gets
// ClusterIssuer resources from the supplied lister
func issuerGetterFromClusterIssuerLister(clusterIssuerLister cmlisters.ClusterIssuerLister) issuerGetter {
	return func(ctx context.Context, _, name string) (cmapi.GenericIssuer, error) {
		issuer, err := clusterIssuerLister.Get(name)
		if err != nil {
			return nil, err
		}
		issuer = issuer.DeepCopy()
		venafidefaults.SetDefaults_ClusterIssuer(issuer)
		return issuer, nil
	}
}

type Controller struct {
	// name is the controller name used in log messages
	name string
	// issuerGetter wraps the fetching of Issuer and ClusterIssuer resources and returns a GenericIssuer
	issuerGetter issuerGetter
	// syncer wraps all the operations that are performed on the GenericIssuer
	// and is only called if the issuer is found and has Venafi configuration
	syncer syncer

	// requeue is called by ProcessItem to schedule its re-execution with key,
	// but only if the Issuer or ClusterIssuer matching key still exists
	// and only if it has Venafi configuration.
	// If it exits with an error, the parent controller-manager will handle
	// retries, with backoff.
	requeue func(key string)
}

func (c *Controller) registerFor(ctx *controllerpkg.Context, name string, issuerType interface{}) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	c.name = name

	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(baseDelay, maxDelay), c.name)
	c.requeue = func(key string) {
		queue.AddAfter(key, recheckDelay)
	}

	secretInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()

	mustSync := []cache.InformerSynced{
		secretInformer.Informer().HasSynced,
	}

	cmClient := ctx.CMClient.CertmanagerV1()
	var issuerSaver issuerSaver

	switch issuerType.(type) {
	case *cmapi.Issuer:
		issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().Issuers()
		mustSync = append(mustSync, issuerInformer.Informer().HasSynced)
		issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})
		c.issuerGetter = issuerGetterFromIssuerLister(issuerInformer.Lister())
		issuerSaver = func(ctx context.Context, issuer cmapi.GenericIssuer) error {
			_, err := cmClient.Issuers(issuer.GetNamespace()).UpdateStatus(ctx, issuer.(*cmapi.Issuer), metav1.UpdateOptions{})
			return err
		}
	case *cmapi.ClusterIssuer:
		issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers()
		mustSync = append(mustSync, issuerInformer.Informer().HasSynced)
		issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})
		c.issuerGetter = issuerGetterFromClusterIssuerLister(issuerInformer.Lister())
		issuerSaver = func(ctx context.Context, issuer cmapi.GenericIssuer) error {
			_, err := cmClient.ClusterIssuers().UpdateStatus(ctx, issuer.(*cmapi.ClusterIssuer), metav1.UpdateOptions{})
			return err
		}
	default:
		panic("unsupported issuerType")
	}

	c.syncer = &saver{
		syncer: &realSyncer{
			venafiClientBuilder: venaficlient.BuilderFromSecretClients(secretInformer.Lister(), ctx.Client.CoreV1(), ctx.IssuerOptions),
		},
		issuerSaver: issuerSaver,
	}

	return queue, mustSync, nil
}

// RegisterForIssuer sets up the Controller for handling Issuer resources
func (c *Controller) RegisterForIssuer(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	return c.registerFor(ctx, ControllerNameIssuer, &cmapi.Issuer{})
}

// RegisterForClusterIssuer sets up the Controller for handling ClusterIssuer resources
func (c *Controller) RegisterForClusterIssuer(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	return c.registerFor(ctx, ControllerNameClusterIssuer, &cmapi.ClusterIssuer{})
}

var (
	errIssuerGetter = errors.New("error getting issuer")
	errSync         = errors.New("error syncing issuer")
)

// ProcessItem parses the resource key, retrieves the resource from the API
// server, checks that it has a Venafi configuration, and then processes it, by
// verifying that the configured Venafi API server can be reached and updating
// the resource Status conditions.
func (c *Controller) ProcessItem(ctx context.Context, key string) (err error) {
	log := logf.FromContext(ctx, c.name, "ProcessItem").WithValues("key", key)
	ctx = logf.NewContext(ctx, log)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "Ignoring invalid key")
		return nil
	}

	issuer, err := c.issuerGetter(ctx, namespace, name)
	if k8serrors.IsNotFound(err) {
		log.V(logf.DebugLevel).Info("Ignoring not-found")
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %v", errIssuerGetter, err)
	}
	if issuer.GetSpec().Venafi == nil {
		log.V(logf.DebugLevel).Info("Ignoring non-venafi issuer")
		return nil
	}
	if err := c.syncer.Sync(ctx, issuer); err != nil {
		return fmt.Errorf("%w: %v", errSync, err)
	}
	c.requeue(key)
	return nil
}
