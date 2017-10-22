package certificates

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
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

func (c *Controller) Sync(ctx context.Context, crt *v1alpha1.Certificate) (err error) {
	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.getGenericIssuer(crt)

	if err != nil {
		s := fmt.Sprintf(messageIssuerNotFound, err.Error())
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerNotFound, s)
		return err
	}

	issuerReady := issuerObj.HasCondition(v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})
	if !issuerReady {
		s := fmt.Sprintf(messageIssuerNotReady, issuerObj.GetObjectMeta().Name)
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
	cert, err := kube.SecretTLSCert(c.secretLister, crt.Namespace, crt.Spec.SecretName)
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

	crtCopy := crt.DeepCopy()
	expectedCN := pki.CommonNameForCertificate(crtCopy)
	expectedDNSNames := pki.DNSNamesForCertificate(crtCopy)

	// if the certificate was not found, or the certificate data is invalid, we
	// should issue a new certificate.
	// if the certificate is valid for a list of domains other than those
	// listed in the certificate spec, we should re-issue the certificate.
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) ||
		expectedCN != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, expectedDNSNames) {
		err := c.issue(ctx, i, crtCopy)
		updateErr := c.updateCertificateStatus(crtCopy)
		if err != nil || updateErr != nil {
			return utilerrors.NewAggregate([]error{err, updateErr})
		}
		return nil
	}

	// calculate the amount of time until expiry
	durationUntilExpiry := cert.NotAfter.Sub(time.Now())
	// calculate how long until we should start attempting to renew the
	// certificate
	renewIn := durationUntilExpiry - renewBefore
	// if we should being attempting to renew now, then trigger a renewal
	if renewIn <= 0 {
		err := c.renew(ctx, i, crtCopy)
		updateErr := c.updateCertificateStatus(crtCopy)
		if err != nil || updateErr != nil {
			return utilerrors.NewAggregate([]error{err, updateErr})
		}
	}

	return nil
}

func (c *Controller) getGenericIssuer(crt *v1alpha1.Certificate) (v1alpha1.GenericIssuer, error) {
	switch crt.Spec.IssuerRef.Kind {
	case "", v1alpha1.IssuerKind:
		return c.issuerLister.Issuers(crt.Namespace).Get(crt.Spec.IssuerRef.Name)
	case v1alpha1.ClusterIssuerKind:
		if c.clusterIssuerLister == nil {
			return nil, fmt.Errorf("cannot get ClusterIssuer for %q as cert-manager is scoped to a single namespace", crt.Name)
		}
		return c.clusterIssuerLister.Get(crt.Spec.IssuerRef.Name)
	default:
		return nil, fmt.Errorf(`invalid value %q for certificate issuer kind. Must be empty, %q or %q`, crt.Spec.IssuerRef.Kind, v1alpha1.IssuerKind, v1alpha1.ClusterIssuerKind)
	}
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

	cert, err := kube.SecretTLSCert(c.secretLister, crt.Namespace, crt.Spec.SecretName)

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

// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) issue(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	var err error
	s := messagePreparingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonPreparingCertificate, s)
	if err = issuer.Prepare(ctx, crt); err != nil {
		s := messageErrorPreparingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return err
	}

	s = messageIssuingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonIssuingCertificate, s)

	var key, cert []byte
	key, cert, err = issuer.Issue(ctx, crt)

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
		Type: api.SecretTypeTLS,
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
func (c *Controller) renew(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	var err error
	s := messagePreparingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonPreparingCertificate, s)

	if err = issuer.Prepare(ctx, crt); err != nil {
		s := messageErrorPreparingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return err
	}

	s = messageRenewingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonRenewingCertificate, s)

	var key, cert []byte
	key, cert, err = issuer.Renew(ctx, crt)

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
		Type: api.SecretTypeTLS,
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

func (c *Controller) updateCertificateStatus(crt *v1alpha1.Certificate) error {
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	_, err := c.cmClient.CertmanagerV1alpha1().Certificates(crt.Namespace).Update(crt)
	return err
}
