/*
Copyright 2021 The cert-manager Authors.

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

package revisionmanager

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/controller/certificates"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/predicate"
)

const (
	ControllerName = "certificates-revision-manager"
)

type controller struct {
	certificateLister        cmlisters.CertificateLister
	certificateRequestLister cmlisters.CertificateRequestLister
	client                   cmclient.Interface
}

type revision struct {
	rev int
	types.NamespacedName
}

func NewController(log logr.Logger, client cmclient.Interface, cmFactory cminformers.SharedInformerFactory) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {
	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := cmFactory.Certmanager().V1().Certificates()
	certificateRequestInformer := cmFactory.Certmanager().V1().CertificateRequests()

	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to any 'owned' CertificateRequest resources
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ResourceOwnerOf,
		),
	})

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateRequestInformer.Informer().HasSynced,
		certificateInformer.Informer().HasSynced,
	}

	return &controller{
		certificateLister:        certificateInformer.Lister(),
		certificateRequestLister: certificateRequestInformer.Lister(),
		client:                   client,
	}, queue, mustSync
}

// ProcessItem will attempt to garbage collect old CertificateRequests based
// upon `spec.revisionHistoryLimit`. This controller will only act on
// Certificates which are in a Ready state and this value is set.
func (c *controller) ProcessItem(ctx context.Context, key string) error {
	log := logf.FromContext(ctx).WithValues("key", key)

	ctx = logf.NewContext(ctx, log)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "invalid resource key passed to ProcessItem")
		return nil
	}

	crt, err := c.certificateLister.Certificates(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		log.Error(err, "certificate not found for key")
		return nil
	}
	if err != nil {
		return err
	}

	log = logf.WithResource(log, crt)

	// If RevisionHistoryLimit is nil, don't attempt to garbage collect old
	// CertificateRequests
	if crt.Spec.RevisionHistoryLimit == nil {
		return nil
	}

	// Only garbage collect over Certificates that are in a Ready=True condition.
	if !apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		return nil
	}

	// Get all CertificateRequests that are owned by this Certificate
	requests, err := certificates.ListCertificateRequestsMatchingPredicates(
		c.certificateRequestLister.CertificateRequests(crt.Namespace), labels.Everything(), predicate.ResourceOwnedBy(crt))
	if err != nil {
		return err
	}

	// Fetch and delete all CertificateRequests that need to be deleted
	limit := int(*crt.Spec.RevisionHistoryLimit)
	toDelete := certificateRequestsToDelete(log, limit, requests)

	for _, req := range toDelete {
		logf.WithRelatedResourceName(log, req.Name, req.Namespace, cmapi.CertificateRequestKind).
			WithValues("revision", req.rev).Info("garbage collecting old certificate request revsion")
		err = c.client.CertmanagerV1().CertificateRequests(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// certificateRequestsToDelete will prune the given CertificateRequests for
// those that have a valid revision number set, and return a slice of requests
// that should be deleted according to the limit given. Oldest
// CertificateRequests by revision will be returned.
func certificateRequestsToDelete(log logr.Logger, limit int, requests []*cmapi.CertificateRequest) []revision {
	// If the number of requests is the same or below the limit, return nothing.
	if limit >= len(requests) {
		return nil
	}

	// Prune and sort all CertificateRequests by their revision number.
	var revisions []revision
	for _, req := range requests {
		log = logf.WithRelatedResource(log, req)

		if req.Annotations == nil || req.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] == "" {
			log.Error(errors.New("skipping processing request with missing revsion"), "")
			continue
		}

		rn, err := strconv.Atoi(req.Annotations[cmapi.CertificateRequestRevisionAnnotationKey])
		if err != nil {
			log.Error(err, "failed to parse request revsion")
			continue
		}

		revisions = append(revisions, revision{rn, types.NamespacedName{Namespace: req.Namespace, Name: req.Name}})
	}

	sort.SliceStable(revisions, func(i, j int) bool {
		return revisions[i].rev < revisions[j].rev
	})

	// Return the oldest revsions which are over the limit
	remaining := len(revisions) - limit
	if remaining < 0 {
		return nil
	}

	return revisions[:remaining]
}

// controllerWrapper wraps the `controller` structure to make it implement
// the controllerpkg.queueingController interface
type controllerWrapper struct {
	*controller
}

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	ctrl, queue, mustSync := NewController(log, ctx.CMClient, ctx.SharedInformerFactory)
	c.controller = ctrl

	return queue, mustSync, nil
}

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(&controllerWrapper{}).
			Complete()
	})
}
