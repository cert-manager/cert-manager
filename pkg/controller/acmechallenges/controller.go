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
	"time"

	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/jetstack/cert-manager/pkg/acme"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/acmechallenges/scheduler"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type Controller struct {
	*controllerpkg.BaseController

	helper     issuer.Helper
	acmeHelper acme.Helper

	challengeLister     cmlisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

	// ACME challenge solvers are instantiated once at the time of controller
	// construction.
	// This also allows for easy mocking of the different challenge mechanisms.
	dnsSolver  solver
	httpSolver solver

	scheduler *scheduler.Scheduler
}

func New(ctx *controllerpkg.Context) (*Controller, error) {
	ctrl := &Controller{}
	bctrl := controllerpkg.New(ctx, ControllerName, ctrl.processNextWorkItem)

	challengeInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Challenges()
	bctrl.AddQueuing(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), "challenges", challengeInformer.Informer())
	ctrl.challengeLister = challengeInformer.Lister()

	// issuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	bctrl.AddWatched(issuerInformer.Informer())
	ctrl.issuerLister = issuerInformer.Lister()

	if ctx.Namespace == "" {
		// clusterIssuerInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: ctrl.queue})
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		bctrl.AddWatched(clusterIssuerInformer.Informer())
		ctrl.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	secretInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()
	bctrl.AddWatched(secretInformer.Informer())
	ctrl.secretLister = secretInformer.Lister()

	// instantiate listers used by the http01 solver
	podInformer := ctx.KubeSharedInformerFactory.Core().V1().Pods()
	serviceInformer := ctx.KubeSharedInformerFactory.Core().V1().Services()
	ingressInformer := ctx.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses()
	bctrl.AddWatched(podInformer.Informer(), serviceInformer.Informer(), ingressInformer.Informer())

	ctrl.BaseController = bctrl
	ctrl.helper = issuer.NewHelper(ctrl.issuerLister, ctrl.clusterIssuerLister)
	ctrl.acmeHelper = acme.NewHelper(ctrl.secretLister, ctrl.BaseController.Context.ClusterResourceNamespace)

	ctrl.httpSolver = http.NewSolver(ctx)
	var err error
	ctrl.dnsSolver, err = dns.NewSolver(ctx)
	if err != nil {
		return nil, err
	}
	ctrl.scheduler = scheduler.New(ctrl.challengeLister, ctx.SchedulerOptions.MaxConcurrentChallenges)

	return ctrl, nil
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
func (c *Controller) runScheduler(ctx context.Context) {
	log := logf.FromContext(ctx, "scheduler")

	toSchedule, err := c.scheduler.ScheduleN(MaxChallengesPerSchedule)
	if err != nil {
		log.Error(err, "error determining set of challenges that should be scheduled for processing")
		return
	}

	for _, ch := range toSchedule {
		log := logf.WithResource(log, ch)
		ch = ch.DeepCopy()
		ch.Status.Processing = true

		_, err := c.CMClient.CertmanagerV1alpha1().Challenges(ch.Namespace).Update(ch)
		if err != nil {
			log.Error(err, "error scheduling challenge for processing")
			return
		}

		c.Recorder.Event(ch, corev1.EventTypeNormal, "Started", "Challenge scheduled for processing")
	}

	if len(toSchedule) > 0 {
		log.V(logf.DebugLevel).Info("scheduled challenges for processing", "number_scheduled", len(toSchedule))
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key")
		return nil
	}

	ch, err := c.challengeLister.Challenges(namespace).Get(name)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			log.Error(err, "challenge in work queue no longer exists")
			return nil
		}

		return err
	}

	ctx = logf.NewContext(ctx, logf.WithResource(log, ch))
	return c.Sync(ctx, ch)
}

var keyFunc = controllerpkg.KeyFunc

const (
	ControllerName = "challenges"
)

func (c *Controller) Run(workers int, stopCh <-chan struct{}) error {
	return c.BaseController.RunWith(c.runScheduler, time.Second, workers, stopCh)
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		i, err := New(ctx)
		if err != nil {
			return nil, err
		}
		return i.Run, nil
	})
}
