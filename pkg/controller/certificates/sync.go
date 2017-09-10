package certificates

import (
	"crypto/x509"
	"fmt"
	"time"

	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"
	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/util"
	"github.com/jetstack-experimental/cert-manager/pkg/util/errors"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
)

const renewBefore = time.Hour * 24 * 30

const (
	errorIssuerNotFound       = "ErrorIssuerNotFound"
	errorIssuerNotReady       = "ErrorIssuerNotReady"
	errorIssuerInit           = "ErrorIssuerInitialization"
	errorCheckCertificate     = "ErrorCheckCertificate"
	errorGetCertificate       = "ErrorGetCertificate"
	errorPreparingCertificate = "ErrorPrepareCertificate"
	errorIssuingCertificate   = "ErrorIssueCertificate"
	errorRenewingCertificate  = "ErrorRenewCertificate"
	errorSavingCertificate    = "ErrorSaveCertificate"

	reasonPreparingCertificate = "PrepareCertificate"
	reasonIssuingCertificate   = "IssueCertificate"
	reasonRenewingCertificate  = "RenewCertificate"

	successCeritificateIssued  = "CeritifcateIssued"
	successCeritificateRenewed = "CeritifcateRenewed"
	successRenewalScheduled    = "RenewalScheduled"

	messageIssuerNotFound            = "Issuer %s does not exist"
	messageIssuerNotReady            = "Issuer %s not ready"
	messageIssuerErrorInit           = "Error initializing issuer: "
	messageErrorCheckCertificate     = "Error checking existing TLS certificate: "
	messageErrorGetCertificate       = "Error getting TLS certificate: "
	messageErrorPreparingCertificate = "Error preparing issuer for certificate: "
	messageErrorIssuingCertificate   = "Error issuing certificate: "
	messageErrorRenewingCertificate  = "Error renewing certificate: "
	messageErrorSavingCertificate    = "Error saving TLS certificate: "

	messagePreparingCertificate = "Preparing certificate with issuer"
	messageIssuingCertificate   = "Issuing certificate..."
	messageRenewingCertificate  = "Renewing certificate..."

	messageCertificateIssued  = "Certificated issued successfully"
	messageCertificateRenewed = "Certificated renewed successfully"
	messageRenewalScheduled   = "Certificate scheduled for renewal in %d hours"
)

func (c *Controller) Sync(crt *v1alpha1.Certificate) (err error) {
	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.issuerLister.Issuers(crt.Namespace).Get(crt.Spec.Issuer)

	if err != nil {
		s := fmt.Sprintf(messageIssuerNotFound, err.Error())
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerNotFound, s)
		return err
	}

	issuerReady := v1alpha1.IssuerHasCondition(issuerObj, v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})

	if !issuerReady {
		s := fmt.Sprintf(messageIssuerNotReady, issuerObj.Name)
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerNotReady, s)
		return fmt.Errorf(s)
	}

	i, err := c.issuerFactory.IssuerFor(issuerObj)

	if err != nil {
		s := messageIssuerErrorInit + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerInit, s)
		return err
	}

	// grab existing certificate and validate private key
	cert, _, err := kube.GetKeyPair(c.client, crt.Namespace, crt.Spec.SecretName)

	if err != nil {
		s := messageErrorCheckCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorCheckCertificate, s)
	}

	// if an error is returned, and that error is something other than
	// IsNotFound or invalid data, then we should return the error.
	if err != nil && !k8sErrors.IsNotFound(err) && !errors.IsInvalidData(err) {
		return err
	}

	// as there is an existing certificate, or we may create one below, we will
	// run scheduleRenewal to schedule a renewal if required at the end of
	// execution.
	defer c.scheduleRenewal(crt)

	// if the certificate was not found, or the certificate data is invalid, we
	// should issue a new certificate
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) {
		return c.issue(i, crt)
	}

	// if the certificate is valid for a list of domains other than those
	// listed in the certificate spec, we should re-issue the certificate
	if !util.EqualUnsorted(crt.Spec.Domains, cert.DNSNames) {
		return c.issue(i, crt)
	}

	// calculate the amount of time until expiry
	durationUntilExpiry := cert.NotAfter.Sub(time.Now())
	// calculate how long until we should start attempting to renew the
	// certificate
	renewIn := durationUntilExpiry - renewBefore

	// if we should being attempting to renew now, then trigger a renewal
	if renewIn <= 0 {
		return c.renew(i, crt)
	}

	return nil
}

func needsRenew(cert *x509.Certificate) bool {
	durationUntilExpiry := cert.NotAfter.Sub(time.Now())
	renewIn := durationUntilExpiry - renewBefore
	// step three: check if referenced secret is valid (after start & before expiry)
	if renewIn <= 0 {
		return true
	}
	return false
}

func (c *Controller) scheduleRenewal(crt *v1alpha1.Certificate) {
	key, err := keyFunc(crt)

	if err != nil {
		runtime.HandleError(fmt.Errorf("error getting key for certificate resource: %s", err.Error()))
		return
	}

	cert, _, err := kube.GetKeyPair(c.client, crt.Namespace, crt.Spec.SecretName)

	if err != nil {
		runtime.HandleError(fmt.Errorf("[%s/%s] Error getting certificate '%s': %s", crt.Namespace, crt.Name, crt.Spec.SecretName, err.Error()))
		return
	}

	durationUntilExpiry := cert.NotAfter.Sub(time.Now())
	renewIn := durationUntilExpiry - renewBefore

	c.scheduledWorkQueue.Add(key, renewIn)

	s := fmt.Sprintf(messageRenewalScheduled, renewIn/time.Hour)
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, successRenewalScheduled, s)
}

func (c *Controller) prepare(issuer issuer.Interface, crt *v1alpha1.Certificate) (err error) {
	var status v1alpha1.CertificateStatus
	status, err = issuer.Prepare(crt)

	defer func() {
		if saveErr := c.updateCertificateStatus(crt, status); saveErr != nil {
			errs := []error{saveErr}
			if err != nil {
				errs = append(errs, err)
			}
			err = utilerrors.NewAggregate(errs)
		}
	}()

	return
}

// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) issue(issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	s := messagePreparingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonPreparingCertificate, s)

	if err := c.prepare(issuer, crt); err != nil {
		s := messageErrorPreparingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return err
	}

	s = messageIssuingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonIssuingCertificate, s)

	key, cert, err := issuer.Issue(crt)
	if err != nil {
		s := messageErrorIssuingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuingCertificate, s)
		return err
	}

	_, err = kube.EnsureSecret(c.client, &api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crt.Spec.SecretName,
			Namespace: crt.Namespace,
		},
		Data: map[string][]byte{
			api.TLSCertKey:       cert,
			api.TLSPrivateKeyKey: key,
		},
	})

	if err != nil {
		s := messageErrorSavingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorSavingCertificate, s)
		return err
	}

	s = messageCertificateIssued
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, successCeritificateIssued, s)

	return nil
}

// renew will attempt to renew a certificate from the specified issuer, or
// return an error on failure. If renewal is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) renew(issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	s := messagePreparingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonPreparingCertificate, s)

	if err := c.prepare(issuer, crt); err != nil {
		s := messageErrorPreparingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return err
	}

	s = messageRenewingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonRenewingCertificate, s)

	key, cert, err := issuer.Renew(crt)
	if err != nil {
		s := messageErrorRenewingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorRenewingCertificate, s)
		return err
	}

	_, err = kube.EnsureSecret(c.client, &api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crt.Spec.SecretName,
			Namespace: crt.Namespace,
		},
		Data: map[string][]byte{
			api.TLSCertKey:       cert,
			api.TLSPrivateKeyKey: key,
		},
	})

	if err != nil {
		s := messageErrorSavingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorSavingCertificate, s)
		return err
	}

	s = messageCertificateRenewed
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, successCeritificateRenewed, s)

	return nil
}

func (c *Controller) updateCertificateStatus(iss *v1alpha1.Certificate, status v1alpha1.CertificateStatus) error {
	updateCertificate := iss.DeepCopy()
	updateCertificate.Status = status
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	_, err := c.cmClient.CertmanagerV1alpha1().Certificates(iss.Namespace).Update(updateCertificate)
	return err
}
