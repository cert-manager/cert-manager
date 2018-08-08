package certificates

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorIssuerNotFound    = "IssuerNotFound"
	errorIssuerNotReady    = "IssuerNotReady"
	errorIssuerInit        = "IssuerInitError"
	errorSavingCertificate = "SaveCertError"
	errorConfig            = "ConfigError"

	reasonIssuingCertificate  = "IssueCert"
	reasonRenewingCertificate = "RenewCert"

	successCertificateIssued  = "CertIssued"
	successCertificateRenewed = "CertRenewed"

	messageErrorSavingCertificate = "Error saving TLS certificate: "

	messageIssuingCertificate  = "Issuing certificate..."
	messageRenewingCertificate = "Renewing certificate..."

	messageCertificateIssued  = "Certificate issued successfully"
	messageCertificateRenewed = "Certificate renewed successfully"
)

func (c *Controller) Sync(ctx context.Context, crt *v1alpha1.Certificate) (err error) {
	crtCopy := crt.DeepCopy()
	defer func() {
		if _, saveErr := c.updateCertificateStatus(crt, crtCopy); saveErr != nil {
			err = utilerrors.NewAggregate([]error{saveErr, err})
		}
	}()

	el := validation.ValidateCertificate(crtCopy)
	if len(el) > 0 {
		msg := fmt.Sprintf("Resource validation failed: %v", el.ToAggregate())
		crtCopy.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorConfig, msg, false)
		return
	} else {
		for i, c := range crtCopy.Status.Conditions {
			if c.Type == v1alpha1.CertificateConditionReady {
				if c.Reason == errorConfig && c.Status == v1alpha1.ConditionFalse {
					crtCopy.Status.Conditions = append(crtCopy.Status.Conditions[:i], crtCopy.Status.Conditions[i+1:]...)
					break
				}
			}
		}
	}

	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.getGenericIssuer(crtCopy)

	if err != nil {
		s := fmt.Sprintf("Issuer %s does not exist", err.Error())
		glog.Info(s)
		c.Recorder.Event(crtCopy, api.EventTypeWarning, errorIssuerNotFound, s)
		return err
	}

	el = validation.ValidateCertificateForIssuer(crtCopy, issuerObj)
	if len(el) > 0 {
		msg := fmt.Sprintf("Resource validation failed: %v", el.ToAggregate())
		crtCopy.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, errorConfig, msg, false)
		return
	} else {
		for i, c := range crtCopy.Status.Conditions {
			if c.Type == v1alpha1.CertificateConditionReady {
				if c.Reason == errorConfig && c.Status == v1alpha1.ConditionFalse {
					crtCopy.Status.Conditions = append(crtCopy.Status.Conditions[:i], crtCopy.Status.Conditions[i+1:]...)
					break
				}
			}
		}
	}

	issuerReady := issuerObj.HasCondition(v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})
	if !issuerReady {
		s := fmt.Sprintf("Issuer %s not ready", issuerObj.GetObjectMeta().Name)
		glog.Info(s)
		c.Recorder.Event(crtCopy, api.EventTypeWarning, errorIssuerNotReady, s)
		return fmt.Errorf(s)
	}

	i, err := c.IssuerFactory().IssuerFor(issuerObj)
	if err != nil {
		s := "Error initializing issuer: " + err.Error()
		glog.Info(s)
		c.Recorder.Event(crtCopy, api.EventTypeWarning, errorIssuerInit, s)
		return err
	}

	expectedCN := pki.CommonNameForCertificate(crtCopy)
	expectedDNSNames := pki.DNSNamesForCertificate(crtCopy)
	if expectedCN == "" || len(expectedDNSNames) == 0 {
		// TODO: Set certificate invalid condition on certificate resource
		// TODO: remove this check in favour of resource validation
		return fmt.Errorf("certificate must specify at least one of dnsNames or commonName")
	}

	// grab existing certificate and validate private key
	cert, err := kube.SecretTLSCert(c.secretLister, crtCopy.Namespace, crtCopy.Spec.SecretName)
	// if an error is returned, and that error is something other than
	// IsNotFound or invalid data, then we should return the error.
	if err != nil && !k8sErrors.IsNotFound(err) && !errors.IsInvalidData(err) {
		return err
	}

	// as there is an existing certificate, or we may create one below, we will
	// run scheduleRenewal to schedule a renewal if required at the end of
	// execution.
	defer c.scheduleRenewal(crtCopy)

	// if the certificate was not found, or the certificate data is invalid, we
	// should issue a new certificate.
	// if the certificate is valid for a list of domains other than those
	// listed in the certificate spec, we should re-issue the certificate.
	if k8sErrors.IsNotFound(err) || errors.IsInvalidData(err) ||
		expectedCN != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, expectedDNSNames) {
		return c.issue(ctx, i, crtCopy)
	}

	// if we should being attempting to renew now, then trigger a renewal
	if c.Context.IssuerOptions.CertificateNeedsRenew(cert) {
		return c.renew(ctx, i, crtCopy)
	}

	return nil
}

// TODO: replace with a call to controllerpkg.Helper.GetGenericIssuer
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
	renewIn := durationUntilExpiry - c.Context.IssuerOptions.RenewBeforeExpiryDuration

	c.scheduledWorkQueue.Add(key, renewIn)

	glog.Infof("Certificate %s/%s scheduled for renewal in %d hours", crt.Namespace, crt.Name, renewIn/time.Hour)
}

// issuerKind returns the kind of issuer for a certificate
func issuerKind(crt *v1alpha1.Certificate) string {
	if crt.Spec.IssuerRef.Kind == "" {
		return v1alpha1.IssuerKind
	} else {
		return crt.Spec.IssuerRef.Kind
	}
}

func (c *Controller) updateSecret(crt *v1alpha1.Certificate, namespace string, cert, key []byte) (*api.Secret, error) {
	secret, err := c.Client.CoreV1().Secrets(namespace).Get(crt.Spec.SecretName, metav1.GetOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, err
	}
	if k8sErrors.IsNotFound(err) {
		secret = &api.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crt.Spec.SecretName,
				Namespace: namespace,
			},
			Type: api.SecretTypeTLS,
			Data: map[string][]byte{},
		}
	}
	secret.Data[api.TLSCertKey] = cert
	secret.Data[api.TLSPrivateKeyKey] = key

	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}

	// Note: since this sets annotations based on certificate resource, incorrect
	// annotations will be set if resource and actual certificate somehow get out
	// of sync
	dnsNames := pki.DNSNamesForCertificate(crt)
	cn := pki.CommonNameForCertificate(crt)

	secret.Annotations[v1alpha1.AltNamesAnnotationKey] = strings.Join(dnsNames, ",")
	secret.Annotations[v1alpha1.CommonNameAnnotationKey] = cn

	secret.Annotations[v1alpha1.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
	secret.Annotations[v1alpha1.IssuerKindAnnotationKey] = issuerKind(crt)

	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}

	secret.Labels[v1alpha1.CertificateNameKey] = crt.Name

	// if it is a new resource
	if secret.SelfLink == "" {
		secret, err = c.Client.CoreV1().Secrets(namespace).Create(secret)
	} else {
		secret, err = c.Client.CoreV1().Secrets(namespace).Update(secret)
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) issue(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	var err error
	glog.Infof("Preparing certificate %s/%s with issuer", crt.Namespace, crt.Name)
	if err = issuer.Prepare(ctx, crt); err != nil {
		glog.Infof("Error preparing issuer for certificate %s/%s: %v", crt.Namespace, crt.Name, err)
		return err
	}

	s := messageIssuingCertificate
	glog.Info(s)
	c.Recorder.Event(crt, api.EventTypeNormal, reasonIssuingCertificate, s)

	var key, cert []byte
	key, cert, err = issuer.Issue(ctx, crt)

	if err != nil {
		glog.Infof("Error issuing certificate for %s/%s: %v", crt.Namespace, crt.Name, err)
		return err
	}

	if _, err := c.updateSecret(crt, crt.Namespace, cert, key); err != nil {
		s := messageErrorSavingCertificate + err.Error()
		glog.Info(s)
		c.Recorder.Event(crt, api.EventTypeWarning, errorSavingCertificate, s)
		return err
	}

	s = messageCertificateIssued
	glog.Info(s)
	c.Recorder.Event(crt, api.EventTypeNormal, successCertificateIssued, s)
	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertificateIssued, s, true)

	return nil
}

// renew will attempt to renew a certificate from the specified issuer, or
// return an error on failure. If renewal is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) renew(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	var err error
	glog.Infof("Preparing certificate %s/%s with issuer", crt.Namespace, crt.Name)
	if err = issuer.Prepare(ctx, crt); err != nil {
		glog.Infof("Error preparing issuer for certificate %s/%s: %v", crt.Namespace, crt.Name, err)
		return err
	}

	s := messageRenewingCertificate
	glog.Info(s)
	c.Recorder.Event(crt, api.EventTypeNormal, reasonRenewingCertificate, s)

	var key, cert []byte
	key, cert, err = issuer.Renew(ctx, crt)

	if err != nil {
		return err
	}

	if _, err := c.updateSecret(crt, crt.Namespace, cert, key); err != nil {
		s := messageErrorSavingCertificate + err.Error()
		glog.Info(s)
		c.Recorder.Event(crt, api.EventTypeWarning, errorSavingCertificate, s)
		return err
	}

	s = messageCertificateRenewed
	glog.Info(s)
	c.Recorder.Event(crt, api.EventTypeNormal, successCertificateRenewed, s)
	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, successCertificateRenewed, s, true)

	return nil
}

func (c *Controller) updateCertificateStatus(old, new *v1alpha1.Certificate) (*v1alpha1.Certificate, error) {
	if reflect.DeepEqual(old.Status, new.Status) {
		return nil, nil
	}
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	return c.CMClient.CertmanagerV1alpha1().Certificates(new.Namespace).Update(new)
}
