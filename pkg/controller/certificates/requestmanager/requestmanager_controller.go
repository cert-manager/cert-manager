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

package requestmanager

import (
	"bytes"
	"context"
	"crypto"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	"github.com/cert-manager/cert-manager/pkg/controller/certificates"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/pkg/util/predicate"
)

const (
	ControllerName = "CertificateRequestManager"
)

var (
	certificateGvk = cmapi.SchemeGroupVersion.WithKind("Certificate")
)

type controller struct {
	certificateLister        cmlisters.CertificateLister
	certificateRequestLister cmlisters.CertificateRequestLister
	secretLister             corelisters.SecretLister
	client                   cmclient.Interface
	recorder                 record.EventRecorder
}

func NewController(
	log logr.Logger,
	client cmclient.Interface,
	factory informers.SharedInformerFactory,
	cmFactory cminformers.SharedInformerFactory,
	recorder record.EventRecorder,
) (*controller, workqueue.RateLimitingInterface, []cache.InformerSynced) {
	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*1, time.Second*30), ControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := cmFactory.Certmanager().V1().Certificates()
	certificateRequestInformer := cmFactory.Certmanager().V1().CertificateRequests()
	secretsInformer := factory.Core().V1().Secrets()

	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to any 'owned' CertificateRequest resources
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ResourceOwnerOf,
		),
	})
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		// Trigger reconciles on changes to any 'owned' secret resources
		WorkFunc: certificates.EnqueueCertificatesForResourceUsingPredicates(log, queue, certificateInformer.Lister(), labels.Everything(),
			predicate.ResourceOwnerOf,
		),
	})

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		secretsInformer.Informer().HasSynced,
		certificateRequestInformer.Informer().HasSynced,
		certificateInformer.Informer().HasSynced,
	}

	return &controller{
		certificateLister:        certificateInformer.Lister(),
		certificateRequestLister: certificateRequestInformer.Lister(),
		secretLister:             secretsInformer.Lister(),
		client:                   client,
		recorder:                 recorder,
	}, queue, mustSync
}

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

	if !apiutil.CertificateHasCondition(crt, cmapi.CertificateCondition{
		Type:   cmapi.CertificateConditionIssuing,
		Status: cmmeta.ConditionTrue,
	}) {
		return nil
	}

	// Check for and fetch the 'status.nextPrivateKeySecretName' secret
	if crt.Status.NextPrivateKeySecretName == nil {
		log.V(logf.DebugLevel).Info("status.nextPrivateKeySecretName not yet set, waiting for keymanager before processing certificate")
		return nil
	}
	nextPrivateKeySecret, err := c.secretLister.Secrets(crt.Namespace).Get(*crt.Status.NextPrivateKeySecretName)
	if apierrors.IsNotFound(err) {
		log.V(logf.DebugLevel).Info("nextPrivateKeySecretName Secret resource does not exist, waiting for keymanager to create it before continuing")
		return nil
	}
	if err != nil {
		return err
	}
	if nextPrivateKeySecret.Data == nil || len(nextPrivateKeySecret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		log.V(logf.DebugLevel).Info("Next private key secret does not contain any valid data, waiting for keymanager before processing certificate")
		return nil
	}
	pk, err := pki.DecodePrivateKeyBytes(nextPrivateKeySecret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		log.Error(err, "Failed to decode next private key secret data, waiting for keymanager before processing certificate")
		return nil
	}

	// Discover all 'owned' CertificateRequests
	requests, err := certificates.ListCertificateRequestsMatchingPredicates(c.certificateRequestLister.CertificateRequests(crt.Namespace), labels.Everything(), predicate.ResourceOwnedBy(crt))
	if err != nil {
		return err
	}

	// delete any existing CertificateRequest resources that do not have a
	// revision annotation
	if requests, err = c.deleteRequestsWithoutRevision(ctx, requests...); err != nil {
		return err
	}

	currentCertificateRevision := 0
	if crt.Status.Revision != nil {
		currentCertificateRevision = *crt.Status.Revision
	}
	nextRevision := currentCertificateRevision + 1

	requests, err = requestsWithRevision(requests, nextRevision)
	if err != nil {
		return err
	}

	requests, err = c.deleteRequestsNotMatchingSpec(ctx, crt, pk.Public(), requests...)
	if err != nil {
		return err
	}

	if len(requests) > 1 {
		// TODO: we should handle this case better, but for now do nothing to
		//  avoid getting into loops where we keep creating multiple requests
		//  and deleting them again.
		log.V(logf.ErrorLevel).Info("Multiple matching CertificateRequest resources exist, delete one of them. This is likely an error and should be reported on the issue tracker!")
		return nil
	}

	if len(requests) == 1 {
		// Nothing to do as we've already verified that the CertificateRequest
		// is up to date above.
		return nil
	}

	return c.createNewCertificateRequest(ctx, crt, pk, nextRevision, nextPrivateKeySecret.Name)
}

func (c *controller) deleteRequestsWithoutRevision(ctx context.Context, reqs ...*cmapi.CertificateRequest) ([]*cmapi.CertificateRequest, error) {
	log := logf.FromContext(ctx)
	var remaining []*cmapi.CertificateRequest
	for _, req := range reqs {
		log := logf.WithRelatedResource(log, req)
		if req.Annotations == nil || req.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] == "" {
			log.V(logf.DebugLevel).Info("Deleting CertificateRequest as it does not contain a revision annotation")
			if err := c.client.CertmanagerV1().CertificateRequests(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{}); err != nil {
				return nil, err
			}
			continue
		}
		reqRevisionStr := req.Annotations[cmapi.CertificateRequestRevisionAnnotationKey]
		_, err := strconv.ParseInt(reqRevisionStr, 10, 0)
		if err != nil {
			log.V(logf.DebugLevel).Info("Deleting CertificateRequest as it contains an invalid revision annotation")
			if err := c.client.CertmanagerV1().CertificateRequests(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{}); err != nil {
				return nil, err
			}
			continue
		}

		remaining = append(remaining, req)
	}
	return remaining, nil
}

func requestsWithRevision(reqs []*cmapi.CertificateRequest, revision int) ([]*cmapi.CertificateRequest, error) {
	var remaining []*cmapi.CertificateRequest
	for _, req := range reqs {
		if req.Annotations == nil || req.Annotations[cmapi.CertificateRequestRevisionAnnotationKey] == "" {
			return nil, fmt.Errorf("certificaterequest %q does not contain revision annotation", req.Name)
		}
		reqRevisionStr := req.Annotations[cmapi.CertificateRequestRevisionAnnotationKey]
		reqRevision, err := strconv.ParseInt(reqRevisionStr, 10, 0)
		if err != nil {
			return nil, err
		}

		if reqRevision == int64(revision) {
			remaining = append(remaining, req)
		}
	}
	return remaining, nil
}

func (c *controller) deleteRequestsNotMatchingSpec(ctx context.Context, crt *cmapi.Certificate, publicKey crypto.PublicKey, reqs ...*cmapi.CertificateRequest) ([]*cmapi.CertificateRequest, error) {
	log := logf.FromContext(ctx)
	var remaining []*cmapi.CertificateRequest
	for _, req := range reqs {
		log := logf.WithRelatedResource(log, req)
		violations, err := certificates.RequestMatchesSpec(req, crt.Spec)
		if err != nil {
			log.Error(err, "Failed to check if CertificateRequest matches spec, deleting CertificateRequest")
			if err := c.client.CertmanagerV1().CertificateRequests(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{}); err != nil {
				return nil, err
			}
			continue
		}
		if len(violations) > 0 {
			log.V(logf.InfoLevel).WithValues("violations", violations).Info("CertificateRequest does not match requirements on certificate.spec, deleting CertificateRequest", "violations", violations)
			if err := c.client.CertmanagerV1().CertificateRequests(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{}); err != nil {
				return nil, err
			}
			continue
		}
		x509Req, err := pki.DecodeX509CertificateRequestBytes(req.Spec.Request)
		if err != nil {
			// this case cannot happen as RequestMatchesSpec would have returned an error too
			return nil, err
		}
		matches, err := pki.PublicKeyMatchesCSR(publicKey, x509Req)
		if err != nil {
			return nil, err
		}
		if !matches {
			log.V(logf.DebugLevel).Info("CertificateRequest contains a CSR that does not have the same public key as the stored next private key secret, deleting CertificateRequest")
			if err := c.client.CertmanagerV1().CertificateRequests(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{}); err != nil {
				return nil, err
			}
			continue
		}
		remaining = append(remaining, req)
	}
	return remaining, nil
}

func (c *controller) createNewCertificateRequest(ctx context.Context, crt *cmapi.Certificate, pk crypto.Signer, nextRevision int, nextPrivateKeySecretName string) error {
	log := logf.FromContext(ctx)
	x509CSR, err := pki.GenerateCSR(crt)
	if err != nil {
		log.Error(err, "Failed to generate CSR - will not retry")
		return nil
	}
	csrDER, err := pki.EncodeCSR(x509CSR, pk)
	if err != nil {
		return err
	}

	csrPEM := bytes.NewBuffer([]byte{})
	err = pem.Encode(csrPEM, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err != nil {
		return err
	}

	annotations := make(map[string]string)
	for k, v := range crt.Annotations {
		annotations[k] = v
	}
	annotations[cmapi.CertificateRequestRevisionAnnotationKey] = strconv.Itoa(nextRevision)
	annotations[cmapi.CertificateRequestPrivateKeyAnnotationKey] = nextPrivateKeySecretName
	annotations[cmapi.CertificateNameKey] = crt.Name

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       crt.Namespace,
			GenerateName:    apiutil.DNSSafeShortenTo52Characters(crt.Name) + "-",
			Annotations:     annotations,
			Labels:          crt.Labels,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			Request:   csrPEM.Bytes(),
			IsCA:      crt.Spec.IsCA,
			Usages:    crt.Spec.Usages,
		},
	}

	cr, err = c.client.CertmanagerV1().CertificateRequests(cr.Namespace).Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	c.recorder.Eventf(crt, corev1.EventTypeNormal, "Requested", "Created new CertificateRequest resource %q", cr.Name)
	if err := c.waitForCertificateRequestToExist(cr.Namespace, cr.Name); err != nil {
		return fmt.Errorf("failed whilst waiting for CertificateRequest to exist - this may indicate an apiserver running slowly. Request will be retried")
	}
	return nil
}

func (c *controller) waitForCertificateRequestToExist(namespace, name string) error {
	return wait.Poll(time.Millisecond*100, time.Second*5, func() (bool, error) {
		_, err := c.certificateRequestLister.CertificateRequests(namespace).Get(name)
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

// controllerWrapper wraps the `controller` structure to make it implement
// the controllerpkg.queueingController interface
type controllerWrapper struct {
	*controller
}

func (c *controllerWrapper) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ControllerName)

	ctrl, queue, mustSync := NewController(log,
		ctx.CMClient,
		ctx.KubeSharedInformerFactory,
		ctx.SharedInformerFactory,
		ctx.Recorder,
	)
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
