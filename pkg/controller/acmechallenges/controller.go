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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	"github.com/jetstack/cert-manager/pkg/acme"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/acmechallenges/scheduler"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/http"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

type controller struct {
	// issuer helper is used to obtain references to issuers, used by Sync()
	helper issuer.Helper
	// acmehelper is used to obtain references to ACME clients
	acmeHelper acme.Helper

	// all the listers used by this controller
	challengeLister     cmlisters.ChallengeLister
	issuerLister        cmlisters.IssuerLister
	clusterIssuerLister cmlisters.ClusterIssuerLister
	secretLister        corelisters.SecretLister

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
	// clientset used to update cert-manager API resources
	cmClient cmclient.Interface

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue workqueue.RateLimitingInterface

	// logger to be used by this controller
	log logr.Logger

	dns01Nameservers []string
}

func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	c.log = logf.FromContext(ctx.RootContext, ControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), ControllerName)

	// obtain references to all the informers used by this controller
	challengeInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Challenges()
	issuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers()
	secretInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()
	// we register these informers here so the HTTP01 solver has a synced
	// cache when managing pod/service/ingress resources
	podInformer := ctx.KubeSharedInformerFactory.Core().V1().Pods()
	serviceInformer := ctx.KubeSharedInformerFactory.Core().V1().Services()
	ingressInformer := ctx.KubeSharedInformerFactory.Extensions().V1beta1().Ingresses()
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

	// set all the references to the listers for used by the Sync function
	c.challengeLister = challengeInformer.Lister()
	c.issuerLister = issuerInformer.Lister()
	c.secretLister = secretInformer.Lister()

	// if we are running in non-namespaced mode (i.e. --namespace=""), we also
	// register event handlers and obtain a lister for clusterissuers.
	if ctx.Namespace == "" {
		clusterIssuerInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers()
		mustSync = append(mustSync, clusterIssuerInformer.Informer().HasSynced)
		c.clusterIssuerLister = clusterIssuerInformer.Lister()
	}

	// register handler functions
	challengeInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})

	c.helper = issuer.NewHelper(c.issuerLister, c.clusterIssuerLister)
	c.acmeHelper = acme.NewHelper(c.secretLister, ctx.ClusterResourceNamespace)
	c.scheduler = scheduler.New(logf.NewContext(ctx.RootContext, c.log), c.challengeLister, ctx.SchedulerOptions.MaxConcurrentChallenges)
	c.recorder = ctx.Recorder
	c.cmClient = ctx.CMClient
	c.httpSolver = http.NewSolver(ctx)
	var err error
	c.dnsSolver, err = dns.NewSolver(ctx)
	if err != nil {
		return nil, nil, err
	}

	// read options from context
	c.dns01Nameservers = ctx.ACMEOptions.DNS01Nameservers

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

	for _, ch := range toSchedule {
		log := logf.WithResource(log, ch)
		ch = ch.DeepCopy()
		ch.Status.Processing = true

		_, err := c.cmClient.CertmanagerV1alpha1().Challenges(ch.Namespace).Update(ch)
		if err != nil {
			log.Error(err, "error scheduling challenge for processing")
			return
		}

		c.recorder.Event(ch, corev1.EventTypeNormal, "Started", "Challenge scheduled for processing")
	}

	if len(toSchedule) > 0 {
		log.V(logf.DebugLevel).Info("scheduled challenges for processing", "number_scheduled", len(toSchedule))
	}
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
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

const (
	ControllerName = "challenges"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		c := &controller{}
		b, err := controllerpkg.New(ctx, ControllerName, c)
		if err != nil {
			return nil, err
		}
		return b.RunWith(c.runScheduler, time.Second), nil
	})
}
