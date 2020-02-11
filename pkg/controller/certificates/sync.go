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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	"github.com/jetstack/cert-manager/pkg/controller/certificates/codec"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func (c *certificateRequestManager) ProcessItem(ctx context.Context, key string) error {
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
	ctx = logf.NewContext(ctx, log)
	updatedCert := crt.DeepCopy()

	defer metrics.Default.UpdateCertificateExpiry(updatedCert, c.secretLister)
	defer metrics.Default.UpdateCertificateStatus(updatedCert)

	err = c.processCertificate(ctx, updatedCert)
	log.V(logf.DebugLevel).Info("check if certificate status update is required")
	updateStatusErr := c.updateCertificateStatus(ctx, crt, updatedCert)
	return utilerrors.NewAggregate([]error{err, updateStatusErr})
}

func (c *certificateRequestManager) updateCertificateStatus(ctx context.Context, old, crt *cmapi.Certificate) error {
	log := logf.FromContext(ctx)
	secretExists := true

	meta, bundle, err := c.secretStore.Fetch(crt.Spec.SecretName, crt.Namespace)
	if err != nil {
		if !apierrors.IsNotFound(err) && !errors.IsInvalidData(err) {
			return err
		}

		if apierrors.IsNotFound(err) {
			secretExists = false
		}
		bundle = &codec.Bundle{}
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
	if len(bundle.Certificates) > 0 {
		cert = bundle.Certificates[0]
		certExpired = cert.NotAfter.Before(c.clock.Now())
	}

	var matches bool
	var matchErrs []string
	if bundle.PrivateKey != nil && cert != nil {
		matches, matchErrs = certificateMatchesSpec(crt, bundle.PrivateKey, cert, meta)
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
	ready := cmmeta.ConditionFalse
	reason := ""
	message := ""
	switch {
	case !secretExists || bundle.PrivateKey == nil:
		reason = "NotFound"
		message = "Certificate does not exist"
	case matches && !isTempCert && !certExpired:
		ready = cmmeta.ConditionTrue
		reason = "Ready"
		message = "Certificate is up to date and has not expired"
	case apiutil.CertificateRequestHasInvalidRequest(req):
		reason = "InvalidRequest"
		message = fmt.Sprintf("The certificate request could not be completed due to invalid request options: %s",
			apiutil.CertificateRequestInvalidRequestMessage(req))
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
			"key_is_nil", bundle.PrivateKey == nil,
			"req_is_nil", req == nil,
			"cert_is_nil", cert == nil,
		)
		ready = cmmeta.ConditionFalse
		reason = "Unknown"
		message = "Unknown certificate status. Please open an issue and share your controller logs."
	}
	apiutil.SetCertificateCondition(crt, cmapi.CertificateConditionReady, ready, reason, message)

	_, err = updateCertificateStatus(ctx, c.cmClient, old, crt)
	if err != nil {
		return err
	}

	return nil
}

// processCertificate is the core method that is called in the manager.
// It accepts a Certificate resource, and checks to see if the certificate
// requires re-issuance.
func (c *certificateRequestManager) processCertificate(ctx context.Context, crt *cmapi.Certificate) error {
	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	// The certificate request name is a product of the certificate's spec,
	// which makes it unique and predictable.
	// First we compute what we expect it to be.
	expectedReqName, err := apiutil.ComputeCertificateRequestName(crt)
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
	secretMeta, bundle, err := c.secretStore.Fetch(crt.Spec.SecretName, crt.Namespace)
	if apierrors.IsNotFound(err) || bundle == nil {
		// If the secret does not exist, generate a new private key and store it.
		dbg.Info("existing secret not found, generating and storing private key")
		return c.generateAndStorePrivateKey(crt)
	}
	if errors.IsInvalidData(err) {
		dbg.Info("failed to decode part of existing secret object: " + err.Error())
	} else if err != nil {
		return err
	}

	// If the Secret does not contain a private key, generate one and update
	// the Secret resource
	if bundle.PrivateKey == nil {
		log.Info("existing private key not found in Secret, generate a new private key")
		return c.generateAndStorePrivateKey(crt)
	}

	// Ensure the the private key has the correct key algorithm and key size.
	dbg.Info("validating private key has correct keyAlgorithm/keySize")
	// If the private key is not 'up to date', we generate a new private key
	if !privateKeyUpToDate(log, bundle.PrivateKey, crt) {
		log.Info("existing private key does not match requirements specified on Certificate resource, generating new private key")
		return c.generateAndStorePrivateKey(crt)
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
	var existingX509Cert *x509.Certificate
	if len(bundle.Certificates) > 0 {
		existingX509Cert = bundle.Certificates[0]
	}
	if existingX509Cert != nil {
		// Here we check to see if the existing certificate 'matches' the spec
		// of the Certificate resource.
		// This includes checking if dnsNames, commonName, organization etc.
		// are up to date, as well as validating that the stored private key is
		// a valid partner to the stored certificate.
		var matchErrs []string
		dbg.Info("checking if existing certificate stored in Secret resource is not expiring soon and matches certificate spec")
		needsIssue, matchErrs = c.certificateRequiresIssuance(ctx, crt, bundle.PrivateKey, existingX509Cert, secretMeta)
		if needsIssue {
			dbg.Info("will attempt to issue certificate", "reason", matchErrs)
		}
	}

	// Exit early if the certificate doesn't need issuing to save extra work
	if !needsIssue {
		dbg.Info("existing certificate does not need re-issuance")
		if existingReq != nil {
			dbg.Info("skipping issuing certificate data into Secret resource as existing issued certificate is still valid")
		}

		// Before exiting, ensure that the Secret resource's metadata is up to
		// date. If it isn't, it will be updated.
		updated, err := c.secretStore.EnsureMetadata(crt, *bundle)
		if err != nil {
			return err
		}

		if updated {
			c.recorder.Event(crt, corev1.EventTypeNormal, "UpdateMeta", "Updated metadata on Secret resource")
			log.Info("updated Secret resource metadata as it was out of date")
		}

		// As the Certificate has been validated as Ready, schedule a renewal
		// for near the expiry date.
		scheduleRenewal(ctx, c.secretLister, c.calculateDurationUntilRenew, c.scheduledWorkQueue.Add, crt)

		log.Info("certificate does not require re-issuance. certificate renewal scheduled near expiry time.")

		return nil
	}

	// Handling for 'temporary certificates'
	if certificateHasTemporaryCertificateAnnotation(crt) {
		// Issue a temporary certificate if the current certificate is empty or the
		// private key is not valid for the current certificate.
		if existingX509Cert == nil {
			log.Info("no existing certificate data found in secret, issuing temporary certificate")
			return c.issueTemporaryCertificate(crt, bundle.PrivateKey)
		}

		matches, err := pki.PublicKeyMatchesCertificate(bundle.PrivateKey.Public(), existingX509Cert)
		if err != nil || !matches {
			log.Info("private key for certificate does not match, issuing temporary certificate")
			return c.issueTemporaryCertificate(crt, bundle.PrivateKey)
		}

		log.Info("not issuing temporary certificate as existing certificate is sufficient")

		// Ensure the secret metadata is up to date
		updated, err := c.secretStore.EnsureMetadata(crt, *bundle)
		if err != nil {
			return err
		}

		// Only return early if an update actually occurred, otherwise continue.
		if updated {
			log.Info("updated Secret resource metadata as it was out of date")
			c.recorder.Event(crt, corev1.EventTypeNormal, "UpdateMeta", "Updated metadata on Secret resource")
			return nil
		}
	}

	if existingReq == nil {
		// If no existing CertificateRequest resource exists, we must create one
		log.Info("no existing CertificateRequest resource exists, creating new request...")
		req, err := c.buildCertificateRequest(crt, expectedReqName, bundle.PrivateKey)
		if err != nil {
			return err
		}

		req, err = c.cmClient.CertmanagerV1alpha2().CertificateRequests(crt.Namespace).Create(req)
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
	if errors.IsInvalidData(err) {
		log.Info("failed to decode existing CSR on CertificateRequest, deleting resource...")
		return c.cmClient.CertmanagerV1alpha2().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
	}
	if err != nil {
		return err
	}

	// Ensure the stored private key is a 'pair' to the CSR
	publicKeyMatches, err := pki.PublicKeyMatchesCSR(bundle.PrivateKey.Public(), x509CSR)
	if err != nil {
		return err
	}

	// if the stored private key does not pair with the CSR on the
	// CertificateRequest resource, delete the resource as we won't be able to
	// do anything with the certificate if it is issued
	if !publicKeyMatches {
		log.Info("stored private key is not valid for CSR stored on existing CertificateRequest, recreating CertificateRequest resource")
		err := c.cmClient.CertmanagerV1alpha2().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
		if err != nil {
			return err
		}

		c.recorder.Eventf(crt, corev1.EventTypeNormal, "PrivateKeyLost", "Lost private key for CertificateRequest %q, deleting old resource", existingReq.Name)
		log.Info("deleted existing CertificateRequest as the stored private key does not match the CSR")
		return nil
	}

	reason := apiutil.CertificateRequestReadyReason(existingReq)

	// If the CertificateRequest condition is present and has the status of
	// "True" then do not attempt to retry the CertificateRequest. Else we can
	// retry.
	if apiutil.CertificateRequestHasInvalidRequest(existingReq) {
		log.Info("CertificateRequest is in an InvalidRequest state and will no longer be processed", "state", reason)

		c.recorder.Eventf(crt, corev1.EventTypeWarning, "CertificateRequestInvalidRequest", "The failed CertificateRequest %q is an invalid request and will no longer be processed", existingReq.Name)
		return nil
	}

	// Determine the status reason of the CertificateRequest and process accordingly
	switch reason {

	// If the CertificateRequest exists but has failed then we check the if the
	// failure time doesn't exist or is over an hour in the past then delete the
	// request so it can be re-created on the next sync. If the failure time is
	// less than an hour in the past then schedule this owning Certificate for a
	// re-sync in an hour.
	case cmapi.CertificateRequestReasonFailed:
		if existingReq.Status.FailureTime == nil || c.clock.Since(existingReq.Status.FailureTime.Time) > time.Hour {
			log.Info("deleting failed certificate request")
			err := c.cmClient.CertmanagerV1alpha2().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
			if err != nil {
				return err
			}

			c.recorder.Eventf(crt, corev1.EventTypeNormal, "CertificateRequestRetry", "The failed CertificateRequest %q will be retried now", existingReq.Name)
			return nil
		}

		log.Info("the failed existing certificate request failed less than an hour ago, will be scheduled for reprocessing in an hour")

		key, err := keyFunc(crt)
		if err != nil {
			log.Error(err, "error getting key for certificate resource")
			return nil
		}

		// We don't fire an event here as this could be called multiple times in quick succession
		c.scheduledWorkQueue.Add(key, time.Hour)
		return nil

		// If the CertificateRequest is in a Ready state then we can decode,
		// verify, and check whether it needs renewal
	case cmapi.CertificateRequestReasonIssued:
		log.Info("CertificateRequest is in a Ready state, issuing certificate...")

		var caCerts []*x509.Certificate
		if len(existingReq.Status.CA) > 0 {
			log.Info("decoding certificate data")
			caCerts, err = pki.DecodeX509CertificateChainBytes(existingReq.Status.CA)
			if err != nil {
				return err
			}
		}
		// Decode the certificate bytes so we can ensure the certificate is valid
		log.Info("decoding certificate data")
		x509Certs, err := pki.DecodeX509CertificateChainBytes(existingReq.Status.Certificate)
		if err != nil {
			return err
		}

		log.Info("checking stored private key is valid for stored x509 certificate on CertificateRequest")
		publicKeyMatches, err := pki.PublicKeyMatchesCertificate(bundle.PrivateKey.Public(), x509Certs[0])
		if err != nil {
			return err
		}
		if !publicKeyMatches {
			log.Info("private key stored in Secret does not match public key of issued certificate, deleting the old CertificateRequest resource")
			return c.cmClient.CertmanagerV1alpha2().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
		}

		// Check if the Certificate requires renewal according to the renewBefore
		// specified on the Certificate resource.
		log.Info("checking if certificate stored on CertificateRequest is up to date")
		if c.certificateNeedsRenew(ctx, x509Certs[0], crt) {
			log.Info("certificate stored on CertificateRequest needs renewal, so deleting the old CertificateRequest resource")
			err := c.cmClient.CertmanagerV1alpha2().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
			if err != nil {
				return err
			}

			return nil
		}

		// If certificate stored on CertificateRequest is not expiring soon, copy
		// across the status.certificate field into the Secret resource.
		log.Info("CertificateRequest contains a valid certificate for issuance. Issuing certificate...")

		if err := c.secretStore.Store(crt.Spec.SecretName, codec.Bundle{
			PrivateKey:   bundle.PrivateKey,
			Certificates: x509Certs,
			CA:           caCerts,
		}, crt, nil); err != nil {
			return err
		}

		c.recorder.Eventf(crt, corev1.EventTypeNormal, "Issued", "Certificate issued successfully")
		return nil

		// If it is not Ready _OR_ Failed then we return and wait for informer
		// updates to re-trigger processing.
	default:
		log.Info("CertificateRequest is not in a final state, waiting until CertificateRequest is complete", "state", reason)
		return nil
	}
}

func (c *certificateRequestManager) issueTemporaryCertificate(crt *cmapi.Certificate, key crypto.Signer) error {
	tempCert, err := c.localTemporarySigner(crt, key)
	if err != nil {
		return err
	}

	if err := c.secretStore.Store(crt.Spec.SecretName, codec.Bundle{
		PrivateKey:   key,
		Certificates: []*x509.Certificate{tempCert},
	}, crt, nil); err != nil {
		return err
	}

	c.recorder.Eventf(crt, corev1.EventTypeNormal, "TempCert", "Issued temporary certificate")

	return nil
}

func (c *certificateRequestManager) certificateRequiresIssuance(ctx context.Context, crt *cmapi.Certificate, key crypto.Signer, cert *x509.Certificate, meta map[string]string) (bool, []string) {
	if isTemporaryCertificate(cert) {
		return true, nil
	}
	matches, matchErrs := certificateMatchesSpec(crt, key, cert, meta)
	if !matches {
		return true, matchErrs
	}
	needsRenew := c.certificateNeedsRenew(ctx, cert, crt)
	return needsRenew, []string{"Certificate is expiring soon"}
}

type generateCSRFn func(*cmapi.Certificate, crypto.Signer) ([]byte, error)

func generateCSRImpl(crt *cmapi.Certificate, signer crypto.Signer) ([]byte, error) {
	csr, err := pki.GenerateCSR(crt)
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

func (c *certificateRequestManager) buildCertificateRequest(crt *cmapi.Certificate, name string, pk crypto.Signer) (*cmapi.CertificateRequest, error) {
	csrPEM, err := c.generateCSR(crt, pk)
	if err != nil {
		return nil, err
	}

	annotations := make(map[string]string, len(crt.Annotations)+2)
	for k, v := range crt.Annotations {
		annotations[k] = v
	}
	annotations[cmapi.CRPrivateKeyAnnotationKey] = crt.Spec.SecretName
	annotations[cmapi.CertificateNameKey] = crt.Name

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       crt.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)},
			Annotations:     annotations,
			Labels:          crt.Labels,
		},
		Spec: cmapi.CertificateRequestSpec{
			CSRPEM:    csrPEM,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
			Usages:    crt.Spec.Usages,
		},
	}

	return cr, nil
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

		err = c.cmClient.CertmanagerV1alpha2().CertificateRequests(req.Namespace).Delete(req.Name, nil)
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

// privateKeyUpToDate will evaluate the private key data in pk and
// ensure it is 'up to date' and matches the specification of the key as
// required by the given Certificate resource.
// It returns false if the private key isn't up to date, e.g. the Certificate
// resource specifies a different keyEncoding, keyAlgorithm or keySize.
func privateKeyUpToDate(log logr.Logger, signer crypto.Signer, crt *cmapi.Certificate) bool {
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
			return false
		}
	// TODO: check keySize
	case cmapi.ECDSAKeyAlgorithm:
		_, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			log.Info("expected private key's algorithm to be ECDSA but it is not")
			return false
		}
		// TODO: check keySize
	}

	return true
}

func (c *certificateRequestManager) generateAndStorePrivateKey(crt *cmapi.Certificate) error {
	signer, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return err
	}

	if err := c.secretStore.Store(crt.Spec.SecretName, codec.Bundle{
		PrivateKey: signer,
	}, crt, nil); err != nil {
		return err
	}

	c.recorder.Eventf(crt, corev1.EventTypeNormal, "GeneratedKey", "Generated a new private key")

	return nil
}

type generatePrivateKeyFn func(*cmapi.Certificate) (crypto.Signer, error)
