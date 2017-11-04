package certificates

import (
	"context"
	"crypto/x509"
	"fmt"
	"sort"
	"time"

	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
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
	// get an issuer resource. we get a generic issuer here so we can support
	// ClusterIssuers as well as Issuers without forking the code
	issuerObj, err := c.getGenericIssuer(crt)
	if err != nil {
		s := fmt.Sprintf(messageIssuerNotFound, err.Error())
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerNotFound, s)
		return err
	}

	// check if the issuer is ready
	issuerReady := issuerObj.HasCondition(v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})
	// if the issuer is not ready, we throw an error so the certificate can be
	// processed again later
	if !issuerReady {
		s := fmt.Sprintf(messageIssuerNotReady, issuerObj.GetObjectMeta().Name)
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerNotReady, s)
		return fmt.Errorf(s)
	}

	// get an issuer implementation for the issuer specified on the certificate
	i, err := c.issuerFactory.IssuerFor(issuerObj)
	if err != nil {
		s := messageIssuerErrorInit + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorIssuerInit, s)
		return err
	}

	// attempt to get a copy of the existing certificate
	cert, err := kube.SecretTLSCert(c.secretLister, crt.Namespace, crt.Spec.SecretName)
	if err != nil {
		s := messageErrorCheckCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeNormal, errorCheckCertificate, s)
	}

	// if an error is returned, and that error is something other than
	// IsNotFound or invalid data, then we should return the error.
	if err != nil && !k8sErrors.IsNotFound(err) && !errors.IsInvalidData(err) {
		return err
	}

	// make a copy of the Certificate from the cache, so we can modify it
	crtCopy := crt.DeepCopy()
	expectedCN := pki.CommonNameForCertificate(crtCopy)
	expectedDNSNames := pki.DNSNamesForCertificate(crtCopy)

	glog.V(4).Infof("Checking certificate validity. Expect CN %q and dnsNames %q", expectedCN, expectedDNSNames)
	switch {
	case k8sErrors.IsNotFound(err):
		glog.V(4).Infof("Issuing certificate as existing certificate is not found")
	case errors.IsInvalidData(err):
		glog.V(4).Infof("Issuing certificate as existing certificate contains invalid data")
	case expectedCN != cert.Subject.CommonName:
		glog.V(4).Infof("Issuing certificate as existing certificate has common name %q, but should be %q", cert.Subject.CommonName, expectedCN)
	case !util.EqualUnsorted(cert.DNSNames, expectedDNSNames):
		sortedActualNames := cert.DNSNames
		sortedExpectedNames := expectedDNSNames
		sort.Strings(sortedActualNames)
		sort.Strings(sortedExpectedNames)
		glog.V(4).Infof("Issuing certificate as existing certificate has DNSNames %q, but should be %q", sortedActualNames, sortedExpectedNames)
	}
	if cert == nil {
		err = c.issue(ctx, i, crtCopy)
	} else {
		// calculate the amount of time until expiry
		durationUntilExpiry := cert.NotAfter.Sub(time.Now())
		// if we should being attempting to renew now, then trigger a renewal
		if durationUntilExpiry <= renewBefore {
			err = c.renew(ctx, i, crtCopy)
		}
	}

	updateErr := c.updateCertificateStatus(crtCopy)
	if err != nil || updateErr != nil {
		return utilerrors.NewAggregate([]error{err, updateErr})
	}

	c.scheduleRenewal(crt)
	return nil
}

func (c *Controller) getGenericIssuer(crt *v1alpha1.Certificate) (v1alpha1.GenericIssuer, error) {
	if crt.Spec.IssuerRef.Name == "" {
		return nil, fmt.Errorf("certificate.spec.issuerRef.name is a required field")
	}

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

func (c *Controller) prepare(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	if crt.Spec.SecretName == "" {
		return fmt.Errorf("certificate.spec.secretName is a required field")
	}

	s := messagePreparingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonPreparingCertificate, s)
	// check we can create and update the certificate secret before we continue
	allowed, reason, err := kube.CanI(c.client, crt.Namespace, "create,update", certmanager.GroupName, "secrets", crt.Spec.SecretName)
	if err != nil {
		s := messageErrorPreparingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return err
	}
	if !allowed {
		s := messageErrorPreparingCertificate + reason
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return fmt.Errorf(s)
	}
	if err = issuer.Prepare(ctx, crt); err != nil {
		s := messageErrorPreparingCertificate + err.Error()
		glog.Info(s)
		c.recorder.Event(crt, api.EventTypeWarning, errorPreparingCertificate, s)
		return err
	}
	return nil
}

// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) issue(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	if err := c.prepare(ctx, issuer, crt); err != nil {
		return err
	}

	s := messageIssuingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonIssuingCertificate, s)

	key, cert, err := issuer.Issue(ctx, crt)

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
	if err := c.prepare(ctx, issuer, crt); err != nil {
		return err
	}

	s := messageRenewingCertificate
	glog.Info(s)
	c.recorder.Event(crt, api.EventTypeNormal, reasonRenewingCertificate, s)

	key, cert, err := issuer.Renew(ctx, crt)

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
