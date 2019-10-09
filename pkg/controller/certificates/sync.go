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
	"encoding/pem"
	"fmt"
	"reflect"
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
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
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
	err = c.processCertificate(ctx, updatedCert)
	log.V(logf.DebugLevel).Info("check if certificate status update is required")
	updateStatusErr := c.updateCertificateStatus(ctx, crt, updatedCert)
	return utilerrors.NewAggregate([]error{err, updateStatusErr})
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
		secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
		if err != nil {
			return err
		}

		matches, matchErrs = certificateMatchesSpec(crt, key, cert, secret)
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
	case !secretExists || key == nil:
		reason = "NotFound"
		message = "Certificate does not exist"
	case matches && !isTempCert && !certExpired:
		ready = cmmeta.ConditionTrue
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
		ready = cmmeta.ConditionFalse
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
	existingSecret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)
	if apierrors.IsNotFound(err) {
		// If the secret does not exist, generate a new private key and store it.
		dbg.Info("existing secret not found, generating and storing private key")
		return c.generateAndStorePrivateKey(ctx, crt, nil)
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
		return c.generateAndStorePrivateKey(ctx, crt, existingSecret)
	}

	// Ensure the the private key has the correct key algorithm and key size.
	dbg.Info("validating private key has correct keyAlgorithm/keySize")
	validKey, err := validatePrivateKeyUpToDate(log, existingKey, crt)
	// If tls.key contains invalid data, we regenerate a new private key
	if errors.IsInvalidData(err) {
		log.Info("existing private key data is invalid, generating a new private key")
		return c.generateAndStorePrivateKey(ctx, crt, existingSecret)
	}
	if err != nil {
		return err
	}
	// If the private key is not 'up to date', we generate a new private key
	if !validKey {
		log.Info("existing private key does not match requirements specified on Certificate resource, generating new private key")
		return c.generateAndStorePrivateKey(ctx, crt, existingSecret)
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
		needsIssue, matchErrs, err = c.certificateRequiresIssuance(ctx, crt, existingKey, existingCert, existingSecret)
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
	if certificateHasTemporaryCertificateAnnotation(crt) {
		// Issue a temporary certificate if the current certificate is empty or the
		// private key is not valid for the current certificate.
		if existingX509Cert == nil {
			log.Info("no existing certificate data found in secret, issuing temporary certificate")
			return c.issueTemporaryCertificate(ctx, existingSecret, crt, existingKey)
		}
		// We don't issue a temporary certificate if the existing stored
		// certificate already 'matches', even if it isn't a temporary certificate.
		matches, _ := certificateMatchesSpec(crt, privateKey, existingX509Cert, existingSecret)
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
		err := c.cmClient.CertmanagerV1alpha2().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
		if err != nil {
			return err
		}

		c.recorder.Eventf(crt, corev1.EventTypeNormal, "PrivateKeyLost", "Lost private key for CertificateRequest %q, deleting old resource", existingReq.Name)
		log.Info("deleted existing CertificateRequest as the stored private key does not match the CSR")
		return nil
	}

	reason := apiutil.CertificateRequestReadyReason(existingReq)
	// Determine the status reason of the CertificateRequest and process accordingly
	switch reason {
	// If the CertificateRequest exists but has failed then we check the failure
	// time. If the failure time doesn't exist or is over an hour in the past
	// then delete the request so it can be re-created on the next sync. If the
	// failure time is less than an hour in the past then schedule this owning
	// Certificate for a re-sync in an hour.
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
			err := c.cmClient.CertmanagerV1alpha2().CertificateRequests(existingReq.Namespace).Delete(existingReq.Name, nil)
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

		// If it is not Ready _OR_ Failed then we return and wait for informer
		// updates to re-trigger processing.
	default:
		log.Info("CertificateRequest is not in a final state, waiting until CertificateRequest is complete", "state", reason)
		return nil
	}
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
	// s will be overwritten by 'existingSecret' if existingSecret is non-nil
	if c.enableSecretOwnerReferences {
		s.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(crt, certificateGvk)}
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
	ca := s.Data[cmmeta.TLSCAKey]

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

func (c *certificateRequestManager) certificateRequiresIssuance(ctx context.Context, crt *cmapi.Certificate, keyBytes, certBytes []byte, secret *corev1.Secret) (bool, []string, error) {
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
	matches, matchErrs := certificateMatchesSpec(crt, key, cert, secret)
	if !matches {
		return true, matchErrs, nil
	}
	needsRenew := c.certificateNeedsRenew(ctx, cert, crt)
	return needsRenew, []string{"Certificate is expiring soon"}, nil
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

func (c *certificateRequestManager) generateAndStorePrivateKey(ctx context.Context, crt *cmapi.Certificate, s *corev1.Secret) error {
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
	s.Data[cmmeta.TLSCAKey] = data.ca

	if s.Annotations == nil {
		s.Annotations = make(map[string]string)
	}

	s.Annotations[cmapi.CertificateNameKey] = crt.Name
	s.Annotations[cmapi.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	s.Annotations[cmapi.IssuerKindAnnotationKey] = apiutil.IssuerKind(crt.Spec.IssuerRef)

	// if the certificate data is empty, clear the subject related annotations
	if len(data.cert) == 0 {
		delete(s.Annotations, cmapi.CommonNameAnnotationKey)
		delete(s.Annotations, cmapi.AltNamesAnnotationKey)
		delete(s.Annotations, cmapi.IPSANAnnotationKey)
		delete(s.Annotations, cmapi.URISANAnnotationKey)
	} else {
		x509Cert, err := pki.DecodeX509CertificateBytes(data.cert)
		// TODO: handle InvalidData here?
		if err != nil {
			return err
		}

		s.Annotations[cmapi.CommonNameAnnotationKey] = x509Cert.Subject.CommonName
		s.Annotations[cmapi.AltNamesAnnotationKey] = strings.Join(x509Cert.DNSNames, ",")
		s.Annotations[cmapi.IPSANAnnotationKey] = strings.Join(pki.IPAddressesToString(x509Cert.IPAddresses), ",")
		s.Annotations[cmapi.URISANAnnotationKey] = strings.Join(pki.URLsToString(x509Cert.URIs), ",")
	}

	return nil
}
