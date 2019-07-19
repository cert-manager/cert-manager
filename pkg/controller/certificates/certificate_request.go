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

package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/feature"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/scheduler"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// certificateRequestManager manages CertificateRequest resources for a
// Certificate in order to obtain signed certs.
type certificateRequestManager struct {
	certificateLister        cmlisters.CertificateLister
	secretLister             corelisters.SecretLister
	certificateRequestLister cmlisters.CertificateRequestLister

	kubeClient kubernetes.Interface
	cmClient   cmclient.Interface

	// maintain a reference to the workqueue for this controller
	// so the handleOwnedResource method can enqueue resources
	queue              workqueue.RateLimitingInterface
	scheduledWorkQueue scheduler.ScheduledWorkQueue

	// used to record Events about resources to the API
	recorder record.EventRecorder

	// used for testing
	clock clock.Clock

	// defined as a field to make it easy to stub out for testing purposes
	generatePrivateKeyBytes generatePrivateKeyBytesFn
	generateCSR             generateCSRFn

	// certificateNeedsRenew is a function that can be used to determine whether
	// a certificate currently requires renewal.
	// This is a field on the controller struct to avoid having to maintain a reference
	// to the controller context, and to make it easier to fake out this call during tests.
	certificateNeedsRenew func(ctx context.Context, cert *x509.Certificate, crt *cmapi.Certificate) bool

	// calculateDurationUntilRenew returns the amount of time before the controller should
	// begin attempting to renew the certificate, given the provided existing certificate
	// and certificate spec.
	// This is a field on the controller struct to avoid having to maintain a reference
	// to the controller context, and to make it easier to fake out this call during tests.
	calculateDurationUntilRenew calculateDurationUntilRenewFn

	// localTemporarySigner signs a certificate that is stored temporarily
	localTemporarySigner localTemporarySignerFn

	// issueTemporaryCerts gates whether temporary certificates should be issued.
	// This is defined here as a bool to make it easy to disable this behaviour.
	issueTemporaryCerts bool
}

type localTemporarySignerFn func(crt *cmapi.Certificate, pk []byte) ([]byte, error)

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *certificateRequestManager) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	// construct a new named logger to be reused throughout the controller
	log := logf.FromContext(ctx.RootContext, ExperimentalControllerName)

	// create a queue used to queue up items to be processed
	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), ExperimentalControllerName)

	// obtain references to all the informers used by this controller
	certificateInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().Certificates()
	certificateRequestInformer := ctx.SharedInformerFactory.Certmanager().V1alpha1().CertificateRequests()
	secretsInformer := ctx.KubeSharedInformerFactory.Core().V1().Secrets()

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		certificateRequestInformer.Informer().HasSynced,
		secretsInformer.Informer().HasSynced,
		certificateInformer.Informer().HasSynced,
	}

	// set all the references to the listers for used by the Sync function
	c.certificateRequestLister = certificateRequestInformer.Lister()
	c.secretLister = secretsInformer.Lister()
	c.certificateLister = certificateInformer.Lister()

	// register handler functions
	certificateInformer.Informer().AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: c.queue})
	certificateRequestInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: controllerpkg.HandleOwnedResourceNamespacedFunc(log, c.queue, certificateGvk, certificateGetter(c.certificateLister))})
	secretsInformer.Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{WorkFunc: secretResourceHandler(log, c.certificateLister, c.queue)})

	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	c.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(c.queue.Add)

	// clock is used to determine whether certificates need renewal
	c.clock = clock.RealClock{}

	// recorder records events about resources to the Kubernetes api
	c.recorder = ctx.Recorder

	c.certificateNeedsRenew = ctx.IssuerOptions.CertificateNeedsRenew
	c.calculateDurationUntilRenew = ctx.IssuerOptions.CalculateDurationUntilRenew
	c.generatePrivateKeyBytes = generatePrivateKeyBytesImpl
	c.generateCSR = generateCSRImpl
	// the localTemporarySigner is used to sign 'temporary certificates' during
	// asynchronous certificate issuance flows
	c.localTemporarySigner = generateLocallySignedTemporaryCertificate
	c.issueTemporaryCerts = utilfeature.DefaultFeatureGate.Enabled(feature.IssueTemporaryCertificate)

	c.cmClient = ctx.CMClient
	c.kubeClient = ctx.Client

	return c.queue, mustSync, nil
}

func (c *certificateRequestManager) ProcessItem(ctx context.Context, key string) error {
	ctx = logf.NewContext(ctx, nil, ExperimentalControllerName)
	log := logf.FromContext(ctx)

	crt, err := getCertificateForKey(ctx, key, c.certificateLister)
	if apierrors.IsNotFound(err) {
		log.Error(err, "certificate resource not found for key", "key", key)
		return nil
	}
	if crt == nil {
		log.Info("certificate resource not found for key", "key", key)
		return nil
	}
	if err != nil {
		return err
	}

	log = logf.WithResource(log, crt)

	if crt.Spec.IssuerRef.Group == "" {
		log.V(logf.DebugLevel).Info("certificate issuerRef.group is not set, skipping processing")
		return nil
	}

	ctx = logf.NewContext(ctx, log)
	updatedCert := crt.DeepCopy()
	err = c.processCertificate(ctx, updatedCert)
	log.V(logf.DebugLevel).Info("check if certificate status update is required")
	updateStatusErr := c.updateCertificateStatus(ctx, crt, updatedCert)
	// TODO: combine errors
	if err != nil {
		return err
	}
	if updateStatusErr != nil {
		return err
	}

	return nil
}

func (c *certificateRequestManager) updateCertificateStatus(ctx context.Context, old, crt *cmapi.Certificate) error {
	log := logf.FromContext(ctx)
	secretExists := true
	certs, key, err := kube.SecretTLSKeyPair(ctx, c.secretLister, crt.Namespace, crt.Spec.SecretName)
	if err != nil {
		if !apierrors.IsNotFound(err) && !errors.IsInvalidData(err) {
			return err
		}

		if apierrors.IsNotFound(err) {
			secretExists = false
		}
	}
	reqs, err := findCertificateRequestsForCertificate(log, crt, c.certificateRequestLister)
	if err != nil {
		return err
	}
	var req *cmapi.CertificateRequest
	if len(reqs) == 1 {
		req = reqs[0]
	}
	var cert *x509.Certificate
	var certExpired bool
	if len(certs) > 0 {
		cert = certs[0]
		certExpired = cert.NotAfter.Before(c.clock.Now())
	}

	var matches bool
	var matchErrs []string
	if key != nil && cert != nil {
		matches, matchErrs = certificateMatchesSpec(crt, key, cert, c.secretLister)
	}

	isTempCert := isTemporaryCertificate(cert)

	// begin setting certificate status fields
	if !matches || isTempCert {
		crt.Status.NotAfter = nil
	} else {
		metaNotAfter := metav1.NewTime(cert.NotAfter)
		crt.Status.NotAfter = &metaNotAfter
	}

	// Derive & set 'Ready' condition on Certificate resource
	ready := cmapi.ConditionFalse
	reason := ""
	message := ""
	switch {
	case !secretExists || key == nil:
		reason = "NotFound"
		message = "Certificate does not exist"
	case matches && !isTempCert && !certExpired:
		ready = cmapi.ConditionTrue
		reason = "Ready"
		message = "Certificate is up to date and has not expired"
	case req != nil:
		reason = "InProgress"
		message = fmt.Sprintf("Waiting for CertificateRequest %q to complete", req.Name)
	case cert == nil:
		reason = "Pending"
		message = "Certificate pending issuance"
	case !matches:
		reason = "DoesNotMatch"
		message = strings.Join(matchErrs, ", ")
	case certExpired:
		reason = "Expired"
		message = fmt.Sprintf("Certificate has expired on %s", cert.NotAfter.Format(time.RFC822))
	case isTempCert:
		reason = "TemporaryCertificate"
		message = "Certificate issuance in progress. Temporary certificate issued."
	default:
		// theoretically, it should not be possible to reach this state.
		// practically, we may have missed some edge cases above.
		// print a dump of the current state as a log message so that users can
		// discover, share and attempt to resolve bugs in this area of code easily.
		log.Info("unknown certificate state",
			"secret_exists", secretExists,
			"matches", matches,
			"is_temp_cert", isTempCert,
			"cert_expired", certExpired,
			"key_is_nil", key == nil,
			"req_is_nil", req == nil,
			"cert_is_nil", cert == nil,
		)
		ready = cmapi.ConditionFalse
		reason = "Unknown"
		message = "Unknown certificate status. Please open an issue and share your controller logs."
	}
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionReady, ready, reason, message)

	_, err = updateCertificateStatus(ctx, metrics.Default, c.cmClient, old, crt)
	if err != nil {
		return err
	}

	return nil
}

// processCertificate is the core method that is called in the manager.
// It accepts a Certificate resource, and checks to see if the certificate
// requires re-issuance.
func (c *certificateRequestManager) processCertificate(ctx context.Context, crt *cmapi.Certificate) error {
	log := logf.FromContext(ctx, ExperimentalControllerName)
	dbg := log.V(logf.DebugLevel)

	// The certificate request name is a product of the certificate's spec,
	// which makes it unique and predictable.
	// First we compute what we expect it to be.
	expectedReqName, err := expectedCertificateRequestName(crt)
	if err != nil {
		return fmt.Errorf("internal error hashing certificate spec: %v", err)
	}

	// Clean up any 'owned' CertificateRequest resources that do not have the
	// expected name computed above
	err = c.cleanupExistingCertificateRequests(log, crt, expectedReqName)
	if err != nil {
		return err
	}

	// Fetch a copy of the existing Secret resource
	existingSecret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if apierrors.IsNotFound(err) {
		// If the secret does not exist, generate a new private key and store it.
		dbg.Info("existing secret not found, generating and storing private key")
		return c.generateAndStorePrivateKey(ctx, crt, nil, c.kubeClient.CoreV1().Secrets(crt.Namespace).Create)
	}
	if err != nil {
		return err
	}

	log = logf.WithRelatedResource(log, existingSecret)
	ctx = logf.NewContext(ctx, log)

	// If the Secret does not contain a private key, generate one and update
	// the Secret resource
	existingKey := existingSecret.Data[corev1.TLSPrivateKeyKey]
	if len(existingKey) == 0 {
		log.Info("existing private key not found in Secret, generate a new private key")
		return c.generateAndStorePrivateKey(ctx, crt, existingSecret, c.kubeClient.CoreV1().Secrets(crt.Namespace).Update)
	}

	// Ensure the the private key has the correct key algorithm and key size.
	dbg.Info("validating private key has correct keyAlgorithm/keySize")
	validKey, err := validatePrivateKeyUpToDate(log, existingKey, crt)
	// If tls.key contains invalid data, we regenerate a new private key
	if errors.IsInvalidData(err) {
		log.Info("existing private key data is invalid, generating a new private key")
		return c.generateAndStorePrivateKey(ctx, crt, existingSecret, c.kubeClient.CoreV1().Secrets(crt.Namespace).Update)
	}
	if err != nil {
		return err
	}
	// If the private key is not 'up to date', we generate a new private key
	if !validKey {
		log.Info("existing private key does not match requirements specified on Certificate resource, generating new private key")
		return c.generateAndStorePrivateKey(ctx, crt, existingSecret, c.kubeClient.CoreV1().Secrets(crt.Namespace).Update)
	}

	// Attempt to fetch the CertificateRequest with the expected name computed above.
	dbg.Info("checking for existing CertificateRequest for Certificate")
	existingReq, err := c.certificateRequestLister.CertificateRequests(crt.Namespace).Get(expectedReqName)
	// Allow IsNotFound errors, later on we check if existingReq == nil and if
	// it is, we create a new CertificateRequest resource.
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if existingReq != nil {
		dbg.Info("found existing certificate request for Certificate", "request_name", existingReq.Name)
		log = logf.WithRelatedResource(log, existingReq)
	}

	needsIssue := true
	// Parse the existing certificate
	existingCert := existingSecret.Data[corev1.TLSCertKey]
	if len(existingCert) > 0 {
		// Here we check to see if the existing certificate 'matches' the spec
		// of the Certificate resource.
		// This includes checking if dnsNames, commonName, organization etc.
		// are up to date, as well as validating that the stored private key is
		// a valid partner to the stored certificate.
		var matchErrs []string
		dbg.Info("checking if existing certificate stored in Secret resource is not expiring soon and matches certificate spec")
		needsIssue, matchErrs, err = c.certificateRequiresIssuance(ctx, crt, existingKey, existingCert)
		if err != nil && !errors.IsInvalidData(err) {
			return err
		}
		// If the certificate data is invalid, we require a re-issuance.
		// The private key should never be invalid at this point as we already
		// check it above.
		if errors.IsInvalidData(err) {
			dbg.Info("existing secret contains invalid certificate data")
			needsIssue = true
		}

		if !needsIssue {
			dbg.Info("existing certificate does not need re-issuance")
		} else {
			dbg.Info("will attempt to issue certificate", "reason", matchErrs)
		}
	}

	// Exit early if the certificate doesn't need issuing to save extra work
	if !needsIssue {
		if existingReq != nil {
			dbg.Info("skipping issuing certificate data into Secret resource as existing issued certificate is still valid")
		}

		// Before exiting, ensure that the Secret resource's metadata is up to
		// date. If it isn't, it will be updated.
		updated, err := c.ensureSecretMetadataUpToDate(ctx, existingSecret, crt)
		if err != nil {
			return err
		}

		if updated {
			log.Info("updated Secret resource metadata as it was out of date")
		}

		// As the Certificate has been validated as Ready, schedule a renewal
		// for near the expiry date.
		scheduleRenewal(ctx, c.secretLister, c.calculateDurationUntilRenew, c.scheduledWorkQueue.Add, crt)

		log.Info("certificate does not require re-issuance. certificate renewal scheduled near expiry time.")

		return nil
	}

	// Attempt to decode the private key.
	// This shouldn't fail as we already validate the private key is valid above.
	dbg.Info("decoding existing private key")
	privateKey, err := pki.DecodePrivateKeyBytes(existingKey)
	if err != nil {
		return err
	}

	// Attempt to decode the existing certificate.
	// We tolerate invalid data errors as we will issue a certificate if the
	// data is invalid.
	dbg.Info("attempting to decode existing certificate")
	existingX509Cert, err := pki.DecodeX509CertificateBytes(existingCert)
	if err != nil && !errors.IsInvalidData(err) {
		return err
	}
	if errors.IsInvalidData(err) {
		dbg.Info("existing certificate data is invalid, continuing...")
	}

	// Handling for 'temporary certificates'
	if c.issueTemporaryCerts {
		// Issue a temporary certificate if the current certificate is empty or the
		// private key is not valid for the current certificate.
		if existingX509Cert == nil {
			log.Info("no existing certificate data found in secret, issuing temporary certificate")
			return c.issueTemporaryCertificate(ctx, existingSecret, crt, existingKey)
		}
		// We don't issue a temporary certificate if the existing stored
		// certificate already 'matches', even if it isn't a temporary certificate.
		matches, _ := certificateMatchesSpec(crt, privateKey, existingX509Cert, c.secretLister)
		if !matches {
			log.Info("existing certificate fields do not match certificate spec, issuing temporary certificate")
			return c.issueTemporaryCertificate(ctx, existingSecret, crt, existingKey)
		}

		log.Info("not issuing temporary certificate as existing certificate matches requirements")

		// Ensure the secret metadata is up to date
		updated, err := c.ensureSecretMetadataUpToDate(ctx, existingSecret, crt)
		if err != nil {
			return err
		}

		// Only return early if an update actually occurred, otherwise continue.
		if updated {
			log.Info("updated Secret resource metadata as it was out of date")
			return nil
		}
	}

	if existingReq == nil {
		// If no existing CertificateRequest resource exists, we must create one
		log.Info("no existing CertificateRequest resource exists, creating new request...")
		req, err := c.buildCertificateRequest(log, crt, expectedReqName, existingKey)
		if err != nil {
			return err
		}

		req, err = c.cmClient.CertmanagerV1alpha1().CertificateRequests(crt.Namespace).Create(req)
		if err != nil {
			return err
		}

		c.recorder.Eventf(crt, corev1.EventTypeNormal, "Requested", "Created new CertificateRequest resource %q", req.Name)
		log.Info("created certificate request", "request_name", req.Name)

		return nil
	}

	// Validate the CertificateRequest's CSR is valid
	log.Info("validating existing CSR data")
	x509CSR, err := pki.DecodeX509CertificateRequestBytes(existingReq.Spec.CSRPEM)
	// TODO: handle InvalidData
	if err != nil {
		return err
	}

	// Ensure the stored private key is a 'pair' to the CSR
	publicKeyMatches, err := pki.PublicKeyMatchesCSR(privateKey.Public(), x509CSR)
	if err != nil {
		return err
	}

	// if the stored private key does not pair with the CSR on the
	// CertificateRequest resource, delete the resource as we won't be able to
	// do anything with the certificate if it is issued
	if !publicKeyMatches {
		log.Info("stored private key is not valid for CSR stored on existing CertificateRequest, recreating CertificateRequest resource")
		err := c.cmClient.CertmanagerV1alpha1().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
		if err != nil {
			return err
		}

		c.recorder.Eventf(crt, corev1.EventTypeNormal, "PrivateKeyLost", "Lost private key for CertificateRequest %q, deleting old resource", existingReq.Name)
		log.Info("deleted existing CertificateRequest as the stored private key does not match the CSR")
		return nil
	}

	// Check if the CertificateRequest is Ready, if it is not then we return
	// and wait for informer updates to re-trigger processing.
	if !apiutil.CertificateRequestHasCondition(existingReq, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmapi.ConditionTrue,
	}) {
		log.Info("certificate request is not in a Ready state, waiting until CertificateRequest is issued")
		// TODO: we need to handle failure states too once we have defined how we represent them
		return nil
	}

	log.Info("CertificateRequest is in a Ready state, issuing certificate...")

	// Decode the certificate bytes so we can ensure the certificate is valid
	log.Info("decoding certificate data")
	x509Cert, err := pki.DecodeX509CertificateBytes(existingReq.Status.Certificate)
	if err != nil {
		return err
	}

	// Check if the Certificate requires renewal according to the renewBefore
	// specified on the Certificate resource.
	log.Info("checking if certificate stored on CertificateRequest is up to date")
	if c.certificateNeedsRenew(ctx, x509Cert, crt) {
		log.Info("certificate stored on CertificateRequest needs renewal, so deleting the old CertificateRequest resource")
		err := c.cmClient.CertmanagerV1alpha1().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
		if err != nil {
			return err
		}

		return nil
	}

	// If certificate stored on CertificateRequest is not expiring soon, copy
	// across the status.certificate field into the Secret resource.
	log.Info("CertificateRequest contains a valid certificate for issuance. Issuing certificate...")

	_, err = c.updateSecretData(ctx, crt, existingSecret, secretData{pk: existingKey, cert: existingReq.Status.Certificate, ca: existingReq.Status.CA})
	if err != nil {
		return err
	}

	c.recorder.Eventf(crt, corev1.EventTypeNormal, "Issued", "Certificate issued successfully")

	return nil
}

// updateSecretData will ensure the Secret resource contains the given secret
// data as well as appropriate metadata.
// If the given 'existingSecret' is nil, a new Secret resource will be created.
// Otherwise, the existing resource will be updated.
// The first return argument will be true if the resource was updated/created
// without error.
func (c *certificateRequestManager) updateSecretData(ctx context.Context, crt *cmapi.Certificate, existingSecret *corev1.Secret, data secretData) (bool, error) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crt.Spec.SecretName,
			Namespace: crt.Namespace,
		},
		Type: corev1.SecretTypeTLS,
	}
	if existingSecret != nil {
		s = existingSecret
	}

	newSecret := s.DeepCopy()
	err := setSecretValues(ctx, crt, newSecret, secretData{pk: data.pk, cert: data.cert, ca: data.ca})
	if err != nil {
		return false, err
	}
	if reflect.DeepEqual(s, newSecret) {
		return false, nil
	}

	if existingSecret == nil {
		_, err = c.kubeClient.CoreV1().Secrets(newSecret.Namespace).Create(newSecret)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	_, err = c.kubeClient.CoreV1().Secrets(newSecret.Namespace).Update(newSecret)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (c *certificateRequestManager) ensureSecretMetadataUpToDate(ctx context.Context, s *corev1.Secret, crt *cmapi.Certificate) (bool, error) {
	pk := s.Data[corev1.TLSPrivateKeyKey]
	cert := s.Data[corev1.TLSCertKey]
	ca := s.Data[TLSCAKey]

	updated, err := c.updateSecretData(ctx, crt, s, secretData{pk: pk, cert: cert, ca: ca})
	if err != nil || !updated {
		return updated, err
	}

	c.recorder.Eventf(crt, corev1.EventTypeNormal, "UpdateMeta", "Updated metadata on Secret resource")

	return true, nil
}

func (c *certificateRequestManager) issueTemporaryCertificate(ctx context.Context, secret *corev1.Secret, crt *cmapi.Certificate, key []byte) error {
	tempCertData, err := c.localTemporarySigner(crt, key)
	if err != nil {
		return err
	}

	newSecret := secret.DeepCopy()
	err = setSecretValues(ctx, crt, newSecret, secretData{pk: key, cert: tempCertData})
	if err != nil {
		return err
	}

	newSecret, err = c.kubeClient.CoreV1().Secrets(newSecret.Namespace).Update(newSecret)
	if err != nil {
		return err
	}

	c.recorder.Eventf(crt, corev1.EventTypeNormal, "TempCert", "Issued temporary certificate")

	return nil
}

func (c *certificateRequestManager) certificateRequiresIssuance(ctx context.Context, crt *cmapi.Certificate, keyBytes, certBytes []byte) (bool, []string, error) {
	key, err := pki.DecodePrivateKeyBytes(keyBytes)
	if err != nil {
		return false, nil, err
	}
	cert, err := pki.DecodeX509CertificateBytes(certBytes)
	if err != nil {
		return false, nil, err
	}
	if isTemporaryCertificate(cert) {
		return true, nil, nil
	}
	matches, matchErrs := certificateMatchesSpec(crt, key, cert, c.secretLister)
	if !matches {
		return true, matchErrs, nil
	}
	needsRenew := c.certificateNeedsRenew(ctx, cert, crt)
	return needsRenew, []string{"Certificate is expiring soon"}, nil
}

func expectedCertificateRequestName(crt *cmapi.Certificate) (string, error) {
	crt = crt.DeepCopy()
	// clear deprecated ACME field as it is not supported with CertificateRequest
	crt.Spec.ACME = nil
	specBytes, err := json.Marshal(crt.Spec)
	if err != nil {
		return "", err
	}

	hashF := fnv.New32()
	_, err = hashF.Write(specBytes)
	if err != nil {
		return "", err
	}

	// shorten the cert name to 52 chars to ensure the total length of the name
	// is less than or equal to 64 characters
	return fmt.Sprintf("%.52s-%d", crt.Name, hashF.Sum32()), nil
}

type generateCSRFn func(*cmapi.Certificate, []byte) ([]byte, error)

func generateCSRImpl(crt *cmapi.Certificate, pk []byte) ([]byte, error) {
	csr, err := pki.GenerateCSR(crt)
	if err != nil {
		return nil, err
	}

	signer, err := pki.DecodePrivateKeyBytes(pk)
	if err != nil {
		return nil, err
	}

	csrDER, err := pki.EncodeCSR(csr, signer)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	})

	return csrPEM, nil
}

func (c *certificateRequestManager) buildCertificateRequest(log logr.Logger, crt *cmapi.Certificate, name string, pk []byte) (*cmapi.CertificateRequest, error) {
	csrPEM, err := c.generateCSR(crt, pk)
	if err != nil {
		return nil, err
	}

	return &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       crt.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
		},
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM:    csrPEM,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
		},
	}, nil
}

func (c *certificateRequestManager) cleanupExistingCertificateRequests(log logr.Logger, crt *cmapi.Certificate, retain string) error {
	reqs, err := findCertificateRequestsForCertificate(log, crt, c.certificateRequestLister)
	if err != nil {
		return err
	}

	for _, req := range reqs {
		log := logf.WithRelatedResource(log, req)
		if req.Name == retain {
			log.V(logf.DebugLevel).Info("skipping deleting CertificateRequest as it is up to date for the certificate spec")
			continue
		}

		err = c.cmClient.CertmanagerV1alpha1().CertificateRequests(req.Namespace).Delete(req.Name, nil)
		if err != nil {
			return err
		}

		log.Info("deleted no longer required CertificateRequest")
	}

	return nil
}

func findCertificateRequestsForCertificate(log logr.Logger, crt *cmapi.Certificate, lister cmlisters.CertificateRequestLister) ([]*cmapi.CertificateRequest, error) {
	log.V(logf.DebugLevel).Info("finding existing CertificateRequest resources for Certificate")
	reqs, err := lister.CertificateRequests(crt.Namespace).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	var candidates []*cmapi.CertificateRequest
	for _, req := range reqs {
		log := logf.WithRelatedResource(log, req)
		if metav1.IsControlledBy(req, crt) {
			log.V(logf.DebugLevel).Info("found CertificateRequest resource for Certificate")
			candidates = append(candidates, &(*req))
		}
	}

	return candidates, nil
}

// validatePrivateKeyUpToDate will evaluate the private key data in pk and
// ensure it is 'up to date' and matches the specification of the key as
// required by the given Certificate resource.
// It returns false if the private key isn't up to date, e.g. the Certificate
// resource specifies a different keyEncoding, keyAlgorithm or keySize.
func validatePrivateKeyUpToDate(log logr.Logger, pk []byte, crt *cmapi.Certificate) (bool, error) {
	signer, err := pki.DecodePrivateKeyBytes(pk)
	if err != nil {
		return false, err
	}

	// TODO: check keyEncoding

	wantedAlgorithm := crt.Spec.KeyAlgorithm
	if wantedAlgorithm == "" {
		// in-memory defaulting of the key algorithm to RSA
		// TODO: remove this in favour of actual defaulting in a mutating webhook
		wantedAlgorithm = cmapi.RSAKeyAlgorithm
	}

	switch wantedAlgorithm {
	case cmapi.RSAKeyAlgorithm:
		_, ok := signer.(*rsa.PrivateKey)
		if !ok {
			log.Info("expected private key's algorithm to be RSA but it is not")
			return false, nil
		}
	// TODO: check keySize
	case cmapi.ECDSAKeyAlgorithm:
		_, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			log.Info("expected private key's algorithm to be ECDSA but it is not")
			return false, nil
		}
		// TODO: check keySize
	}

	return true, nil
}

type secretSaveFn func(*corev1.Secret) (*corev1.Secret, error)

func (c *certificateRequestManager) generateAndStorePrivateKey(ctx context.Context, crt *cmapi.Certificate, s *corev1.Secret, saveFn secretSaveFn) error {
	keyData, err := c.generatePrivateKeyBytes(ctx, crt)
	if err != nil {
		// TODO: handle permanent failures caused by invalid spec
		return err
	}

	updated, err := c.updateSecretData(ctx, crt, s, secretData{pk: keyData})
	if err != nil {
		return err
	}
	if !updated {
		return nil
	}

	c.recorder.Eventf(crt, corev1.EventTypeNormal, "GeneratedKey", "Generated a new private key")

	return nil
}

type generatePrivateKeyBytesFn func(context.Context, *cmapi.Certificate) ([]byte, error)

func generatePrivateKeyBytesImpl(ctx context.Context, crt *cmapi.Certificate) ([]byte, error) {
	signer, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return nil, err
	}

	keyData, err := pki.EncodePrivateKey(signer, crt.Spec.KeyEncoding)
	if err != nil {
		return nil, err
	}

	return keyData, nil
}

// secretData is a structure wrapping private key, certificate and CA data
type secretData struct {
	pk, cert, ca []byte
}

// setSecretValues will update the Secret resource 's' with the data contained
// in the given secretData.
// It will update labels and annotations on the Secret resource appropriately.
// The Secret resource 's' must be non-nil, although may be a resource that does
// not exist in the Kubernetes apiserver yet.
// setSecretValues will NOT actually update the resource in the apiserver.
// If updating an existing Secret resource returned by an api client 'lister',
// make sure to DeepCopy the object first to avoid modifying data in-cache.
func setSecretValues(ctx context.Context, crt *cmapi.Certificate, s *corev1.Secret, data secretData) error {
	// initialize the `Data` field if it is nil
	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}

	s.Data[corev1.TLSPrivateKeyKey] = data.pk
	s.Data[corev1.TLSCertKey] = data.cert
	s.Data[TLSCAKey] = data.ca

	if s.Annotations == nil {
		s.Annotations = make(map[string]string)
	}

	s.Annotations[cmapi.CertificateNameKey] = crt.Name
	s.Annotations[cmapi.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	s.Annotations[cmapi.IssuerKindAnnotationKey] = issuerKind(crt.Spec.IssuerRef)

	// if the certificate data is empty, clear the subject related annotations
	if len(data.cert) == 0 {
		delete(s.Annotations, cmapi.CommonNameAnnotationKey)
		delete(s.Annotations, cmapi.AltNamesAnnotationKey)
		delete(s.Annotations, cmapi.IPSANAnnotationKey)
	} else {
		x509Cert, err := pki.DecodeX509CertificateBytes(data.cert)
		// TODO: handle InvalidData here?
		if err != nil {
			return err
		}

		s.Annotations[cmapi.CommonNameAnnotationKey] = x509Cert.Subject.CommonName
		s.Annotations[cmapi.AltNamesAnnotationKey] = strings.Join(x509Cert.DNSNames, ",")
		s.Annotations[cmapi.IPSANAnnotationKey] = strings.Join(pki.IPAddressesToString(x509Cert.IPAddresses), ",")
	}

	return nil
}

const (
	ExperimentalControllerName = "certificates-experimental"
)

func init() {
	controllerpkg.Register(ExperimentalControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		c, err := controllerpkg.New(ctx, ExperimentalControllerName, &certificateRequestManager{})
		if err != nil {
			return nil, err
		}
		return c.Run, nil
	})
}
