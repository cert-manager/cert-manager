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

package acmechallenges

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/acme"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/acmechallenges/scheduler"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http"
	"github.com/jetstack/cert-manager/pkg/util"
)

type Controller struct {
	controllerpkg.Context

	helper     issuer.Helper
	acmeHelper acme.Helper

	// To allow injection for testing.
	syncHandler func(ctx context.Context, key string) error

	challengeLister     cmlisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	// ACME challenge solvers are instantiated once at the time of controller
	// construction.
	// This also allows for easy mocking of the different challenge mechanisms.
	dnsSolver  solver
	httpSolver solver

	watchedInformers []cache.InformerSynced
	queue            workqueue.RateLimitingInterface

	scheduler *scheduler.Scheduler
}

func New(ctx *controllerpkg.Context) *Controller {
	ctrl := &Controller{Context: *ctx}
	ctrl.syncHandler = ctrl.processNextWorkItem

	ctrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), "challenges")

	challengeInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Challenges()
	challengeInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	ctrl.watchedInformers = append(ctrl.watchedInformers, challengeInformer.Informer().HasSynced)
	ctrl.challengeLister = challengeInformer.Lister()

	// issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	issuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	ctrl.watchedInformers = append(ctrl.watchedInformers, issuerInformer.Informer().HasSynced)
	ctrl.issuerLister = issuerInformer.Lister()

	if ctx.Namespace == "" {
		// clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
		clusterIssuerInformer := ctrl.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		ctrl.watchedInformers = append(ctrl.watchedInformers, clusterIssuerInformer.Informer().HasSynced)
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	secretInformer := ctrl.KubeSharedInformerFactory.Core().V1().Secrets()
	ctrl.watchedInformers = append(ctrl.watchedInformers, secretInformer.Informer().HasSynced)
	ctrl.secretLister = secretInformer.Lister()

	// instantiate listers used by the http01 solver
	podInformer := ctrl.KubeSharedInformerFactory.Core().V1().Pods()
	serviceInformer := ctrl.KubeSharedInformerFactory.Core().V1().Services()
	ingressInformer := ctrl.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses()
	ctrl.watchedInformers = append(ctrl.watchedInformers, podInformer.Informer().HasSynced)
	ctrl.watchedInformers = append(ctrl.watchedInformers, serviceInformer.Informer().HasSynced)
	ctrl.watchedInformers = append(ctrl.watchedInformers, ingressInformer.Informer().HasSynced)

	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.acmeHelper = acme.NewHelper(ctrl.secretLister, ctrl.Context.ClusterResourceNamespace)

	ctrl.httpSolver = http.NewSolver(ctx)
	ctrl.dnsSolver = dns.NewSolver(ctx)
	ctrl.scheduler = scheduler.New(ctrl.challengeLister)

	return ctrl
}

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	klog.V(4).Infof("Starting %s control loop", ControllerName)
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, c.watchedInformers...) {
		// c.challengeInformerSynced) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		// TODO (@munnerz): make time.Second duration configurable
		go wait.Until(func() {
			defer wg.Done()
			c.worker(stopCh)
		},
			time.Second, stopCh)
	}
	// TODO: properly plumb in stopCh and WaitGroup to scheduler
	// Run the scheduler once per second
	go wait.Until(c.runScheduler, time.Second*1, stopCh)

	<-stopCh
	klog.V(4).Infof("Shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	klog.V(4).Infof("Waiting for workers to exit...")
	wg.Wait()
	klog.V(4).Infof("Workers exited.")
	return nil
}

// MaxChallengesPerSchedule is the maximum number of challenges that can be
// scheduled with a single call to the scheduler.
// This provides a very crude rate limit on how many challenges we will schedule
// per second. It may be better to remove this altogether in favour of some
// other method of rate limiting creations.
// TODO: make this configurable
const MaxChallengesPerSchedule = 20

// runScheduler will execute the scheduler's ScheduleN function to determine
// which, if any, challenges should be rescheduled.
// TODO: it should also only re-run the scheduler if a change to challenges has
// been observed, to save needless work
func (c *Controller) runScheduler() {
	toSchedule, err := c.scheduler.ScheduleN(MaxChallengesPerSchedule)
	if err != nil {
		runtime.HandleError(fmt.Errorf("Error determining set of challenges that should be scheduled for processing: %v", err))
		return
	}

	for _, ch := range toSchedule {
		ch = ch.DeepCopy()
		ch.Status.Processing = true

		_, err := c.CMClient.CertmanagerV1alpha1().Challenges(ch.Namespace).Update(ch)
		if err != nil {
			runtime.HandleError(fmt.Errorf("Error scheduling challenge %s/%s for processing: %v", ch.Namespace, ch.Name, err))
			return
		}

		c.Recorder.Event(ch, corev1.EventTypeNormal, "Started", "Challenge scheduled for processing")
	}

	if len(toSchedule) > 0 {
		plural := ""
		if len(toSchedule) > 1 {
			plural = "s"
		}
		klog.V(4).Infof("Scheduled %d challenge%s for processing", len(toSchedule), plural)
	}
}

func (c *Controller) worker(stopCh <-chan struct{}) {
	klog.V(4).Infof("Starting %q worker", ControllerName)
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		var key string
		// use an inlined function so we can use defer
		func() {
			defer c.queue.Done(obj)
			var ok bool
			if key, ok = obj.(string); !ok {
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = util.ContextWithStopCh(ctx, stopCh)
			klog.Infof("%s controller: syncing item '%s'", ControllerName, key)
			if err := c.syncHandler(ctx, key); err != nil {
				klog.Errorf("%s controller: Re-queuing item %q due to error processing: %s", ControllerName, key, err.Error())
				c.queue.AddRateLimited(obj)
				return
			}
			klog.Infof("%s controller: Finished processing work item %q", ControllerName, key)
			c.queue.Forget(obj)
		}()
	}
	klog.V(4).Infof("Exiting %q worker loop", ControllerName)
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	ch, err := c.challengeLister.Challenges(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("ch '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.Sync(ctx, ch)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "challenges"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return New(ctx).Run
	})
}
