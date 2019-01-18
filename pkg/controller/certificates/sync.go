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
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/runtime"

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
)

const (
	TLSCAKey = "ca.crt"
)

var (
	certificateGvk = v1alpha1.SchemeGroupVersion.WithKind("Certificate")
)

// to help testing
var now = time.Now

func (c *Controller) Sync(ctx context.Context, crt *v1alpha1.Certificate) (err error) {
	crtCopy := crt.DeepCopy()
	defer func() {
		if _, saveErr := c.updateCertificateStatus(crt, crtCopy); saveErr != nil {
			err = utilerrors.NewAggregate([]error{saveErr, err})
		}
	}()

	// grab existing certificate and validate private key
	certs, key, err := kube.SecretTLSKeyPair(c.secretLister, crtCopy.Namespace, crtCopy.Spec.SecretName)
	// if we don't have a certificate, we need to trigger a re-issue immediately
	if err != nil && !(k8sErrors.IsNotFound(err) || errors.IsInvalidData(err)) {
		return err
	}

	var cert *x509.Certificate
	if len(certs) > 0 {
		cert = certs[0]
	}

	// update certificate expiry metric
	defer c.metrics.UpdateCertificateExpiry(crtCopy, c.secretLister)
	c.setCertificateStatus(crtCopy, key, cert)

	el := validation.ValidateCertificate(crtCopy)
	if len(el) > 0 {
		c.Recorder.Eventf(crtCopy, corev1.EventTypeWarning, "BadConfig", "Resource validation failed: %v", el.ToAggregate())
		return nil
	}

	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.getGenericIssuer(crtCopy)
	if k8sErrors.IsNotFound(err) {
		c.Recorder.Eventf(crtCopy, corev1.EventTypeWarning, errorIssuerNotFound, err.Error())
		return nil
	}
	if err != nil {
		return err
	}

	el = validation.ValidateCertificateForIssuer(crtCopy, issuerObj)
	if len(el) > 0 {
		c.Recorder.Eventf(crtCopy, corev1.EventTypeWarning, "BadConfig", "Resource validation failed: %v", el.ToAggregate())
		return nil
	}

	// If this is an ACME certificate, ensure the certificate.spec.acme field is
	// non-nil
	if issuerObj.GetSpec().ACME != nil && crtCopy.Spec.ACME == nil {
		c.Recorder.Eventf(crtCopy, corev1.EventTypeWarning, "BadConfig", "spec.acme field must be set")
		return nil
	}

	issuerReady := issuerObj.HasCondition(v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})
	if !issuerReady {
		c.Recorder.Eventf(crtCopy, corev1.EventTypeWarning, errorIssuerNotReady, "Issuer %s not ready", issuerObj.GetObjectMeta().Name)
		return nil
	}

	i, err := c.IssuerFactory().IssuerFor(issuerObj)
	if err != nil {
		c.Recorder.Eventf(crtCopy, corev1.EventTypeWarning, errorIssuerInit, "Internal error initialising issuer: %v", err)
		return nil
	}

	if key == nil || cert == nil {
		glog.V(4).Infof("Invoking issue function as existing certificate does not exist")
		return c.issue(ctx, i, crtCopy)
	}

	// begin checking if the TLS certificate is valid/needs a re-issue or renew
	matches, matchErrs := c.certificateMatchesSpec(crtCopy, key, cert)
	if !matches {
		glog.V(4).Infof("Invoking issue function due to certificate not matching spec: %s", strings.Join(matchErrs, ", "))
		return c.issue(ctx, i, crtCopy)
	}

	// check if the certificate needs renewal
	needsRenew := c.Context.IssuerOptions.CertificateNeedsRenew(cert, crt.Spec.RenewBefore)
	if needsRenew {
		glog.V(4).Infof("Invoking issue function due to certificate needing renewal")
		return c.issue(ctx, i, crtCopy)
	}
	// end checking if the TLS certificate is valid/needs a re-issue or renew

	// If the Certificate is valid and up to date, we schedule a renewal in
	// the future.
	c.scheduleRenewal(crt)

	return nil
}

// setCertificateStatus will update the status subresource of the certificate.
// It will not actually submit the resource to the apiserver.
func (c *Controller) setCertificateStatus(crt *v1alpha1.Certificate, key crypto.Signer, cert *x509.Certificate) {
	if key == nil || cert == nil {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, "NotFound", "Certificate does not exist", false)
		return
	}

	metaNotAfter := metav1.NewTime(cert.NotAfter)
	crt.Status.NotAfter = &metaNotAfter

	// Derive & set 'Ready' condition on Certificate resource
	matches, matchErrs := c.certificateMatchesSpec(crt, key, cert)
	reason := "Ready"
	if cert.NotAfter.Before(now()) {
		reason = "Expired"
		matchErrs = append(matchErrs, fmt.Sprintf("Certificate has expired"))
	}
	if !matches {
		reason = "DoesNotMatch"
	}
	if len(matchErrs) > 0 {
		crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, reason, strings.Join(matchErrs, ", "), false)
		return
	}

	crt.UpdateStatusCondition(v1alpha1.CertificateConditionReady, v1alpha1.ConditionTrue, reason, "Certificate is up to date and has not expired", false)

	return
}

func (c *Controller) certificateMatchesSpec(crt *v1alpha1.Certificate, key crypto.Signer, cert *x509.Certificate) (bool, []string) {
	var errs []string

	// TODO: add checks for KeySize, KeyAlgorithm fields
	// TODO: add checks for Organization field
	// TODO: add checks for IsCA field

	// check if the private key is the corresponding pair to the certificate
	matches, err := pki.PublicKeyMatchesCertificate(key.Public(), cert)
	if err != nil {
		errs = append(errs, err.Error())
	} else if !matches {
		errs = append(errs, fmt.Sprintf("Certificate private key does not match certificate"))
	}

	// validate the common name is correct
	expectedCN := pki.CommonNameForCertificate(crt)
	if expectedCN != cert.Subject.CommonName {
		errs = append(errs, fmt.Sprintf("Common name on TLS certificate not up to date: %q", cert.Subject.CommonName))
	}

	// validate the dns names are correct
	expectedDNSNames := pki.DNSNamesForCertificate(crt)
	if !util.EqualUnsorted(cert.DNSNames, expectedDNSNames) {
		errs = append(errs, fmt.Sprintf("DNS names on TLS certificate not up to date: %q", cert.DNSNames))
	}

	return len(errs) == 0, errs
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
		if !errors.IsInvalidData(err) {
			runtime.HandleError(fmt.Errorf("[%s/%s] Error getting certificate '%s': %s", crt.Namespace, crt.Name, crt.Spec.SecretName, err.Error()))
		}
		return
	}

	renewIn := c.calculateDurationUntilRenew(cert, crt)

	c.scheduledWorkQueue.Add(key, renewIn)

	glog.Infof("Certificate %s/%s scheduled for renewal in %s", crt.Namespace, crt.Name, renewIn.String())
}

// issuerKind returns the kind of issuer for a certificate
func issuerKind(crt *v1alpha1.Certificate) string {
	if crt.Spec.IssuerRef.Kind == "" {
		return v1alpha1.IssuerKind
	} else {
		return crt.Spec.IssuerRef.Kind
	}
}

func ownerRef(crt *v1alpha1.Certificate) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{
		APIVersion: v1alpha1.SchemeGroupVersion.String(),
		Kind:       v1alpha1.CertificateKind,
		Name:       crt.Name,
		UID:        crt.UID,
		Controller: &controller,
	}
}

func (c *Controller) updateSecret(crt *v1alpha1.Certificate, namespace string, cert, key, ca []byte) (*corev1.Secret, error) {
	secret, err := c.Client.CoreV1().Secrets(namespace).Get(crt.Spec.SecretName, metav1.GetOptions{})
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, err
	}
	if k8sErrors.IsNotFound(err) {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crt.Spec.SecretName,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{},
		}
	}

	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[corev1.TLSCertKey] = cert
	secret.Data[corev1.TLSPrivateKeyKey] = key
	secret.Data[TLSCAKey] = ca

	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}

	// If we are updating the Certificate, we update the secret metadata to
	// reflect the actual certificate it contains
	if cert != nil {
		x509Cert, err := pki.DecodeX509CertificateBytes(cert)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate data: %v", err)
		}

		secret.Annotations[v1alpha1.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
		secret.Annotations[v1alpha1.IssuerKindAnnotationKey] = issuerKind(crt)
		secret.Annotations[v1alpha1.CommonNameAnnotationKey] = x509Cert.Subject.CommonName
		secret.Annotations[v1alpha1.AltNamesAnnotationKey] = strings.Join(x509Cert.DNSNames, ",")
	}

	// Always set the certificate name label on the target secret
	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}
	secret.Labels[v1alpha1.CertificateNameKey] = crt.Name

	// if it is a new resource
	if secret.SelfLink == "" {
		enableOwner := c.CertificateOptions.EnableOwnerRef
		if enableOwner {
			secret.SetOwnerReferences(append(secret.GetOwnerReferences(), ownerRef(crt)))
		}
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
	resp, err := issuer.Issue(ctx, crt)
	if err != nil {
		glog.Infof("Error issuing certificate for %s/%s: %v", crt.Namespace, crt.Name, err)
		return err
	}

	if resp == nil {
		return nil
	}

	if _, err := c.updateSecret(crt, crt.Namespace, resp.Certificate, resp.PrivateKey, resp.CA); err != nil {
		s := messageErrorSavingCertificate + err.Error()
		glog.Info(s)
		c.Recorder.Event(crt, corev1.EventTypeWarning, errorSavingCertificate, s)
		return err
	}

	if len(resp.Certificate) > 0 {
		c.Recorder.Event(crt, corev1.EventTypeNormal, successCertificateIssued, "Certificate issued successfully")
		// as we have just written a certificate, we should schedule it for renewal
		c.scheduleRenewal(crt)
	}

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

// calculateDurationUntilRenew calculates how long cert-manager should wait to
// until attempting to renew this certificate resource.
func (c *Controller) calculateDurationUntilRenew(cert *x509.Certificate, crt *v1alpha1.Certificate) time.Duration {
	messageCertificateDuration := "Certificate received from server has a validity duration of %s. The requested certificate validity duration was %s"
	messageScheduleModified := "Certificate renewal duration was changed to fit inside the received certificate validity duration from issuer."

	// validate if the certificate received was with the issuer configured
	// duration. If not we generate an event to warn the user of that fact.
	certDuration := cert.NotAfter.Sub(cert.NotBefore)
	if crt.Spec.Duration != nil && certDuration < crt.Spec.Duration.Duration {
		s := fmt.Sprintf(messageCertificateDuration, certDuration, crt.Spec.Duration.Duration)
		glog.Info(s)
		// TODO Use the message as the reason in a 'renewal status' condition
	}

	// renew is the duration before the certificate expiration that cert-manager
	// will start to try renewing the certificate.
	renewBefore := v1alpha1.DefaultRenewBefore
	if crt.Spec.RenewBefore != nil {
		renewBefore = crt.Spec.RenewBefore.Duration
	}

	// Verify that the renewBefore duration is inside the certificate validity duration.
	// If not we notify with an event that we will renew the certificate
	// before (certificate duration / 3) of its expiration duration.
	if renewBefore > certDuration {
		glog.Info(messageScheduleModified)
		// TODO Use the message as the reason in a 'renewal status' condition
		// We will renew 1/3 before the expiration date.
		renewBefore = certDuration / 3
	}

	// calculate the amount of time until expiry
	durationUntilExpiry := cert.NotAfter.Sub(now())
	// calculate how long until we should start attempting to renew the certificate
	renewIn := durationUntilExpiry - renewBefore

	return renewIn
}
