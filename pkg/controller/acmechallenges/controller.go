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

package acmechallenges

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	internalinformers "github.com/cert-manager/cert-manager/internal/informers"
	"github.com/cert-manager/cert-manager/pkg/acme/accounts"
	cmacmelisters "github.com/cert-manager/cert-manager/pkg/client/listers/acme/v1"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/acmechallenges/scheduler"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/http"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

type controller struct {
	// issuer helper is used to obtain references to issuers, used by Sync()
	helper issuer.Helper

	// used to fetch ACME clients used in the controller
	accountRegistry accounts.Getter

	// all the listers used by this controller
	challengeLister     cmacmelisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        internalinformers.SecretLister

	// ACME challenge solvers are instantiated once at the time of controller
	// construction.
	// This also allows for easy mocking of the different challenge mechanisms.
	dnsSolver  solver
	httpSolver solver
	// scheduler marks challenges as Processing=true if they can be scheduled
	// for processing. This job runs periodically every N seconds, so it cannot
	// be constructed as a traditional controller.
	scheduler *scheduler.Scheduler

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName]

	// logger to be used by this controller
	log logr.Logger

	dns01Nameservers []string

	DNS01CheckRetryPeriod time.Duration

	// objectUpdater implements the updateObject function which is used to save
	// changes to the Challenge.Status and Challenge.Finalizers
	objectUpdater
}

func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.TypedRateLimitingInterface[types.NamespacedName], []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
		controllerpkg.DefaultACMERateLimiter(),
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
			Name: ControllerName,
		},
	)

	// obtain references to all the informers used by this controller
	challengeInformer := ctx.SharedInformerFactory.Acme().V1().Challenges()
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1().Issuers()
	secretInformer := ctx.KubeSharedInformerFactory.Secrets()
	// we register these informers here so the HTTP01 solver has a synced
	// cache when managing pod/service/ingress resources
	podInformer := ctx.HTTP01ResourceMetadataInformersFactory.ForResource(corev1.SchemeGroupVersion.WithResource("pods"))
	serviceInformer := ctx.HTTP01ResourceMetadataInformersFactory.ForResource(corev1.SchemeGroupVersion.WithResource("services"))
	ingressInformer := ctx.KubeSharedInformerFactory.Ingresses()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		challengeInformer.Informer().HasSynced,
		issuerInformer.Informer().HasSynced,
		secretInformer.Informer().HasSynced,
		podInformer.Informer().HasSynced,
		serviceInformer.Informer().HasSynced,
		ingressInformer.Informer().HasSynced,
	}

	if ctx.GatewaySolverEnabled {
		gwAPIHTTPRouteInformer := ctx.GWShared.Gateway().V1().HTTPRoutes()
		mustSync = append(mustSync, gwAPIHTTPRouteInformer.Informer().HasSynced)
	}

	// set all the references to the listers for used by the Sync function
	c.challengeLister = challengeInformer.Lister()
	c.issuerLister = issuerInformer.Lister()
	c.secretLister = secretInformer.Lister()

	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1().ClusterIssuers()
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
		c.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	// register handler functions
	if _, err := challengeInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue}); err != nil {
		return nil, nil, fmt.Errorf("error setting up event handler: %v", err)
	}

	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)
	c.scheduler = scheduler.New(logf.NewContext(ctx.RootContext, c.log), c.challengeLister, ctx.SchedulerOptions.MaxConcurrentChallenges)
	c.recorder = ctx.Recorder
	c.accountRegistry = ctx.ACMEOptions.AccountRegistry

	var err error
	c.httpSolver, err = http.NewSolver(ctx)
	if err != nil {
		return nil, nil, err
	}
	c.dnsSolver, err = dns.NewSolver(ctx)
	if err != nil {
		return nil, nil, err
	}

	// read options from context
	c.dns01Nameservers = ctx.ACMEOptions.DNS01Nameservers
	c.DNS01CheckRetryPeriod = ctx.ACMEOptions.DNS01CheckRetryPeriod

	// Construct an objectUpdater which is used to save changes to the Challenge
	// object, either using Update or using Patch + Server Side Apply.
	c.objectUpdater = newObjectUpdater(ctx.CMClient, ctx.FieldManager)

	return c.queue, mustSync, nil
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
func (c *controller) runScheduler(ctx context.Context) {
	log := logf.FromContext(ctx, "scheduler")

	toSchedule, err := c.scheduler.ScheduleN(MaxChallengesPerSchedule)
	if err != nil {
		log.Error(err, "error determining set of challenges that should be scheduled for processing")
		return
	}

	for _, chOriginal := range toSchedule {
		log := logf.WithResource(log, chOriginal)
		ch := chOriginal.DeepCopy()
		ch.Status.Processing = true
		if err := c.updateObject(ctx, chOriginal, ch); err != nil {
			log.Error(err, "error scheduling challenge for processing")
			return
		}
		c.recorder.Event(ch, corev1.EventTypeNormal, "Started", "Challenge scheduled for processing")
	}

	if len(toSchedule) > 0 {
		log.V(logf.DebugLevel).Info("scheduled challenges for processing", "number_scheduled", len(toSchedule))
	}
}

func (c *controller) ProcessItem(ctx context.Context, key types.NamespacedName) error {
	log := logf.FromContext(ctx)
	namespace, name := key.Namespace, key.Name

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

const (
	ControllerName = "challenges"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.ContextFactory) (controllerpkg.Interface, error) {
		c := &controller{}
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(c).
			With(c.runScheduler, time.Second).
			Complete()
	})
}
