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
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/feature"
	"github.com/jetstack/cert-manager/pkg/issuer"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	utilfeature "github.com/jetstack/cert-manager/pkg/util/feature"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

const (
	errorIssuerNotFound      = "IssuerNotFound"
	errorIssuerNotReady      = "IssuerNotReady"
	errorIssuerInit          = "IssuerInitError"
	errorSavingCertificate   = "SaveCertError"
	errorConfig              = "ConfigError"
	errorDuplicateSecretName = "DuplicateSecretNameError"

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

func (c *controller) Sync(ctx context.Context, crt *v1alpha1.Certificate) (err error) {
	c.metrics.IncrementSyncCallCount(ControllerName)

	log := logf.FromContext(ctx)
	dbg := log.V(logf.DebugLevel)

	// if group name is set, use the new experimental controller implementation
	if crt.Spec.IssuerRef.Group != "" {
		log.Info("certificate issuerRef group is non-empty, skipping processing")
		return nil
	}

	crtCopy := crt.DeepCopy()
	defer func() {
		if _, saveErr := updateCertificateStatus(ctx, c.metrics, c.cmClient, crt, crtCopy); saveErr != nil {
			err = utilerrors.NewAggregate([]error{saveErr, err})
		}
	}()

	dbg.Info("Fetching existing certificate from secret", "name", crtCopy.Spec.SecretName)
	// grab existing certificate and validate private key
	certs, key, err := kube.SecretTLSKeyPair(ctx, c.secretLister, crtCopy.Namespace, crtCopy.Spec.SecretName)
	// if we don't have a certificate, we need to trigger a re-issue immediately
	if err != nil && !(k8sErrors.IsNotFound(err) || errors.IsInvalidData(err)) {
		return err
	}

	var cert *x509.Certificate
	if len(certs) > 0 {
		dbg.Info("Found existing certificate in secret")
		cert = certs[0]
	}

	// update certificate expiry metric
	defer c.metrics.UpdateCertificateExpiry(crtCopy, c.secretLister)
	dbg.Info("Update certificate status if required")
	c.setCertificateStatus(crtCopy, key, cert)

	el := validation.ValidateCertificate(crtCopy)
	if len(el) > 0 {
		c.recorder.Eventf(crtCopy, corev1.EventTypeWarning, "BadConfig", "Resource validation failed: %v", el.ToAggregate())
		return nil
	}

	// check that certificate secret name is unique
	namespaceCrts := c.certificateLister.Certificates(crtCopy.Namespace)
	otherCrts, err := namespaceCrts.List(labels.Everything())
	if err != nil {
		return err
	}
	var duplicate *v1alpha1.Certificate
	for _, otherCrt := range otherCrts {
		if otherCrt.Name != crtCopy.Name && otherCrt.Spec.SecretName == crtCopy.Spec.SecretName {
			duplicate = otherCrt
			break
		}
	}
	if duplicate != nil {
		c.recorder.Eventf(crtCopy, corev1.EventTypeWarning, errorDuplicateSecretName, "Another Certificate %v already specifies spec.secretName %v, please update the secretName on either Certificate", duplicate.Name, crtCopy.Spec.SecretName)
		key, err := cache.MetaNamespaceKeyFunc(crtCopy)
		if err != nil {
			c.recorder.Eventf(crtCopy, corev1.EventTypeWarning, "KeyError", "Failed to create a key for the Certificate: %v", err)
			return nil
		}
		c.scheduledWorkQueue.Forget(key)
		apiutil.SetCertificateCondition(crtCopy, v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, "DuplicateSecretName", "Another Certificate is using the same secretName")
		return nil
	}

	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.helper.GetGenericIssuer(crtCopy.Spec.IssuerRef, crtCopy.Namespace)
	if k8sErrors.IsNotFound(err) {
		c.recorder.Eventf(crtCopy, corev1.EventTypeWarning, errorIssuerNotFound, err.Error())
		return nil
	}
	if err != nil {
		return err
	}
	dbg.Info("Fetched issuer resource referenced by certificate", "issuer_name", crtCopy.Spec.IssuerRef.Name)

	el = validation.ValidateCertificateForIssuer(crtCopy, issuerObj)
	if len(el) > 0 {
		c.recorder.Eventf(crtCopy, corev1.EventTypeWarning, "BadConfig", "Resource validation failed: %v", el.ToAggregate())
		return nil
	}

	dbg.Info("Certificate passed all validation checks")

	issuerReady := apiutil.IssuerHasCondition(issuerObj, v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})
	if !issuerReady {
		c.recorder.Eventf(crtCopy, corev1.EventTypeWarning, errorIssuerNotReady, "Issuer %s not ready", issuerObj.GetObjectMeta().Name)
		return nil
	}

	i, err := c.issuerFactory.IssuerFor(issuerObj)
	if err != nil {
		c.recorder.Eventf(crtCopy, corev1.EventTypeWarning, errorIssuerInit, "Internal error initialising issuer: %v", err)
		return nil
	}

	if isTemporaryCertificate(cert) {
		dbg.Info("Temporary certificate found - calling 'issue'")
		return c.issue(ctx, i, crtCopy)
	}

	if key == nil || cert == nil {
		dbg.Info("Invoking issue function as existing certificate does not exist")
		return c.issue(ctx, i, crtCopy)
	}

	// begin checking if the TLS certificate is valid/needs a re-issue or renew
	matches, matchErrs := certificateMatchesSpec(crtCopy, key, cert, c.secretLister)
	if !matches {
		dbg.Info("invoking issue function due to certificate not matching spec", "diff", strings.Join(matchErrs, ", "))
		return c.issue(ctx, i, crtCopy)
	}

	// check if the certificate needs renewal
	needsRenew := c.certificateNeedsRenew(ctx, cert, crt)
	if needsRenew {
		dbg.Info("invoking issue function due to certificate needing renewal")
		return c.issue(ctx, i, crtCopy)
	}
	// end checking if the TLS certificate is valid/needs a re-issue or renew

	dbg.Info("Certificate does not need updating. Scheduling renewal.")
	// If the Certificate is valid and up to date, we schedule a renewal in
	// the future.
	scheduleRenewal(ctx, c.secretLister, c.calculateDurationUntilRenew, c.scheduledWorkQueue.Add, crt)

	return nil
}

// setCertificateStatus will update the status subresource of the certificate.
// It will not actually submit the resource to the apiserver.
func (c *controller) setCertificateStatus(crt *v1alpha1.Certificate, key crypto.Signer, cert *x509.Certificate) {
	if key == nil || cert == nil {
		apiutil.SetCertificateCondition(crt, v1alpha1.CertificateConditionReady, v1alpha1.ConditionFalse, "NotFound", "Certificate does not exist")
		return
	}

	metaNotAfter := metav1.NewTime(cert.NotAfter)
	crt.Status.NotAfter = &metaNotAfter

	// Derive & set 'Ready' condition on Certificate resource
	matches, matchErrs := certificateMatchesSpec(crt, key, cert, c.secretLister)
	ready := v1alpha1.ConditionFalse
	reason := ""
	message := ""
	switch {
	case isTemporaryCertificate(cert):
		reason = "TemporaryCertificate"
		message = "Certificate issuance in progress. Temporary certificate issued."
		// clear the NotAfter field as it is not relevant to the user
		crt.Status.NotAfter = nil
	case cert.NotAfter.Before(c.clock.Now()):
		reason = "Expired"
		message = fmt.Sprintf("Certificate has expired on %s", cert.NotAfter.Format(time.RFC822))
	case !matches:
		reason = "DoesNotMatch"
		message = strings.Join(matchErrs, ", ")
	default:
		ready = v1alpha1.ConditionTrue
		reason = "Ready"
		message = "Certificate is up to date and has not expired"
	}

	apiutil.SetCertificateCondition(crt, v1alpha1.CertificateConditionReady, ready, reason, message)

	return
}

func certificateMatchesSpec(crt *v1alpha1.Certificate, key crypto.Signer, cert *x509.Certificate, secretLister corelisters.SecretLister) (bool, []string) {
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

	// validate the ip addresses are correct
	if !util.EqualUnsorted(pki.IPAddressesToString(cert.IPAddresses), crt.Spec.IPAddresses) {
		errs = append(errs, fmt.Sprintf("IP addresses on TLS certificate not up to date: %q", pki.IPAddressesToString(cert.IPAddresses)))
	}

	// get a copy of the current secret resource
	// Note that we already know that it exists, no need to check for errors
	// TODO: Refactor so that the secret is passed as argument?
	secret, err := secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)

	// validate that the issuer is correct
	if crt.Spec.IssuerRef.Name != secret.Annotations[v1alpha1.IssuerNameAnnotationKey] {
		errs = append(errs, fmt.Sprintf("Issuer of the certificate is not up to date: %q", secret.Annotations[v1alpha1.IssuerNameAnnotationKey]))
	}

	// validate that the issuer kind is correct
	if issuerKind(crt.Spec.IssuerRef) != secret.Annotations[v1alpha1.IssuerKindAnnotationKey] {
		errs = append(errs, fmt.Sprintf("Issuer kind of the certificate is not up to date: %q", secret.Annotations[v1alpha1.IssuerKindAnnotationKey]))
	}

	return len(errs) == 0, errs
}

func scheduleRenewal(ctx context.Context, lister corelisters.SecretLister, calc calculateDurationUntilRenewFn, queueFn func(interface{}, time.Duration), crt *v1alpha1.Certificate) {
	log := logf.FromContext(ctx)
	log = log.WithValues(
		logf.RelatedResourceNameKey, crt.Spec.SecretName,
		logf.RelatedResourceNamespaceKey, crt.Namespace,
		logf.RelatedResourceKindKey, "Secret",
	)

	key, err := keyFunc(crt)
	if err != nil {
		log.Error(err, "error getting key for certificate resource")
		return
	}

	cert, err := kube.SecretTLSCert(ctx, lister, crt.Namespace, crt.Spec.SecretName)
	if err != nil {
		if !errors.IsInvalidData(err) {
			log.Error(err, "error getting secret for certificate resource")
		}
		return
	}

	renewIn := calc(ctx, cert, crt)
	queueFn(key, renewIn)

	log.WithValues("duration_until_renewal", renewIn.String()).Info("certificate scheduled for renewal")
}

// issuerKind returns the kind of issuer for a certificate
func issuerKind(ref v1alpha1.ObjectReference) string {
	if ref.Kind == "" {
		return v1alpha1.IssuerKind
	}
	return ref.Kind
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

// updateSecret will store the provided secret data into the target secret
// named on the Certificate resource.
// - If the secret is empty, a new one will be created containing the data
// - If a secret already exists, its contents will be overwritten
// - If the provided certificate is a temporary certificate and the certificate
//   stored in the secret is already a temporary certificate, then the Secret
//   **will not** be updated.
func (c *controller) updateSecret(ctx context.Context, crt *v1alpha1.Certificate, namespace string, cert, key, ca []byte) (*corev1.Secret, error) {
	log := logf.FromContext(ctx, "updateSecret")
	log = logf.WithRelatedResourceName(log, crt.Spec.SecretName, namespace, "Secret")

	// if the key is not set, we bail out early.
	// this function should always be called with at least a private key.
	// in future we'll likely need to relax this requirement, but for now we'll
	// keep this here to be safe.
	if len(key) == 0 {
		return nil, fmt.Errorf("private key data must be set")
	}
	privKey, err := pki.DecodePrivateKeyBytes(key)
	if err != nil {
		return nil, fmt.Errorf("error decoding private key: %v", err)
	}

	// get a copy of the current secret resource
	secret, err := c.secretLister.Secrets(namespace).Get(crt.Spec.SecretName)
	if err != nil && !k8sErrors.IsNotFound(err) {
		return nil, err
	}
	// create a deep copy of the secret before modifying it as we fetched it
	// from the lister's cache.
	if secret != nil {
		secret = secret.DeepCopy()
	}
	// if the resource does not already exist, we will create a new one
	if secret == nil {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      crt.Spec.SecretName,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{},
		}
	}
	// include this clause in case the existing secret has nil data
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}

	var existingCert *x509.Certificate
	existingCertData := secret.Data[corev1.TLSCertKey]
	if len(existingCertData) > 0 {
		existingCert, err = pki.DecodeX509CertificateBytes(existingCertData)
		if err != nil {
			log.Error(err, "error decoding existing x509 certificate bytes, continuing anyway")
		}
	}

	var x509Cert *x509.Certificate
	switch {
	case len(cert) > 0:
		x509Cert, err = pki.DecodeX509CertificateBytes(cert)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate data: %v", err)
		}
	case !utilfeature.DefaultFeatureGate.Enabled(feature.IssueTemporaryCertificate):
		break
	case isTemporaryCertificate(existingCert):
		matches, err := pki.PublicKeyMatchesCertificate(privKey.Public(), existingCert)
		if err == nil && matches {
			// if the existing certificate is a temporary one, and the certificate
			// being written in this call to updateSecret is not set, then we do
			// not want to keep re-issuing new temporary certificates
			cert = existingCertData
			x509Cert = existingCert
			break
		}
		fallthrough
	default:
		// if the issuer returns a private key but not certificate data, we
		// generate and store a temporary certificate that we can later
		// recognise and force later calls to the issuer's Issue method
		cert, err = c.localTemporarySigner(crt, key)
		if err != nil {
			return nil, fmt.Errorf("error signing locally generated certificate: %v", err)
		}

		x509Cert, err = pki.DecodeX509CertificateBytes(cert)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate data: %v", err)
		}

		c.recorder.Event(crt, corev1.EventTypeNormal, "GenerateSelfSigned", "Generated temporary self signed certificate")
	}

	// TODO: move metadata setting out of this method, and support
	// retrospectively adding metadata annotations on every Sync iteration and
	// not just when a new certificate is issued
	if x509Cert != nil {
		secret.Annotations[v1alpha1.IssuerNameAnnotationKey] = crt.Spec.IssuerRef.Name
		secret.Annotations[v1alpha1.IssuerKindAnnotationKey] = issuerKind(crt.Spec.IssuerRef)
		secret.Annotations[v1alpha1.CommonNameAnnotationKey] = x509Cert.Subject.CommonName
		secret.Annotations[v1alpha1.AltNamesAnnotationKey] = strings.Join(x509Cert.DNSNames, ",")
		secret.Annotations[v1alpha1.IPSANAnnotationKey] = strings.Join(pki.IPAddressesToString(x509Cert.IPAddresses), ",")
	}

	// Always set the certificate name label on the target secret
	secret.Labels[v1alpha1.CertificateNameKey] = crt.Name

	// set the actual values in the secret
	secret.Data[corev1.TLSCertKey] = cert
	secret.Data[corev1.TLSPrivateKeyKey] = key
	secret.Data[TLSCAKey] = ca

	// if it is a new resource
	if secret.SelfLink == "" {
		if c.addOwnerReferences {
			secret.SetOwnerReferences(append(secret.GetOwnerReferences(), ownerRef(crt)))
		}
		secret, err = c.kClient.CoreV1().Secrets(namespace).Create(secret)
	} else {
		secret, err = c.kClient.CoreV1().Secrets(namespace).Update(secret)
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *controller) issue(ctx context.Context, issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	log := logf.FromContext(ctx)

	resp, err := issuer.Issue(ctx, crt)
	if err != nil {
		log.Error(err, "error issuing certificate")
		return err
	}
	// if the issuer has not returned any data, exit early
	if resp == nil {
		return nil
	}

	if _, err := c.updateSecret(ctx, crt, crt.Namespace, resp.Certificate, resp.PrivateKey, resp.CA); err != nil {
		s := messageErrorSavingCertificate + err.Error()
		log.Error(err, "error saving certificate")
		c.recorder.Event(crt, corev1.EventTypeWarning, errorSavingCertificate, s)
		return err
	}

	if len(resp.Certificate) > 0 {
		c.recorder.Event(crt, corev1.EventTypeNormal, successCertificateIssued, "Certificate issued successfully")
		// as we have just written a certificate, we should schedule it for renewal
		scheduleRenewal(ctx, c.secretLister, c.calculateDurationUntilRenew, c.scheduledWorkQueue.Add, crt)
	}

	return nil
}

// staticTemporarySerialNumber is a fixed serial number we check for when
// updating the status of a certificate.
// It is used to identify temporarily generated certificates, so that friendly
// status messages can be displayed to users.
const staticTemporarySerialNumber = 0x1234567890

func isTemporaryCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return cert.SerialNumber.Int64() == staticTemporarySerialNumber
}

func generateSelfSignedTemporaryCertificate(crt *v1alpha1.Certificate, pk []byte) ([]byte, error) {
	template, err := pki.GenerateTemplate(crt)
	template.SerialNumber = big.NewInt(staticTemporarySerialNumber)

	signer, err := pki.DecodePrivateKeyBytes(pk)
	if err != nil {
		return nil, err
	}

	b, _, err := pki.SignCertificate(template, template, signer.Public(), signer)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// generateLocallySignedTemporaryCertificate signs a temporary certificate for
// the given certificate resource using a one-use temporary CA that is then
// discarded afterwards.
// This is to mitigate a potential attack against x509 certificates that use a
// predictable serial number and weak MD5 hashing algorithms.
// In practice, this shouldn't really be a concern anyway.
func generateLocallySignedTemporaryCertificate(crt *v1alpha1.Certificate, pk []byte) ([]byte, error) {
	// generate a throwaway self-signed root CA
	caPk, err := pki.GenerateECPrivateKey(pki.ECCurve521)
	if err != nil {
		return nil, err
	}
	caCertTemplate, err := pki.GenerateTemplate(&v1alpha1.Certificate{
		Spec: v1alpha1.CertificateSpec{
			CommonName: "cert-manager.local",
			IsCA:       true,
		},
	})
	if err != nil {
		return nil, err
	}
	_, caCert, err := pki.SignCertificate(caCertTemplate, caCertTemplate, caPk.Public(), caPk)
	if err != nil {
		return nil, err
	}

	// sign a temporary certificate using the root CA
	template, err := pki.GenerateTemplate(crt)
	if err != nil {
		return nil, err
	}
	template.SerialNumber = big.NewInt(staticTemporarySerialNumber)

	signeeKey, err := pki.DecodePrivateKeyBytes(pk)
	if err != nil {
		return nil, err
	}

	b, _, err := pki.SignCertificate(template, caCert, signeeKey.Public(), caPk)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func updateCertificateStatus(ctx context.Context, m *metrics.Metrics, cmClient cmclient.Interface, old, new *v1alpha1.Certificate) (*v1alpha1.Certificate, error) {
	defer m.UpdateCertificateStatus(new)

	log := logf.FromContext(ctx, "updateStatus")
	oldBytes, _ := json.Marshal(old.Status)
	newBytes, _ := json.Marshal(new.Status)
	if reflect.DeepEqual(oldBytes, newBytes) {
		return nil, nil
	}
	log.V(logf.DebugLevel).Info("updating resource due to change in status", "diff", pretty.Diff(string(oldBytes), string(newBytes)))
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	return cmClient.CertmanagerV1alpha1().Certificates(new.Namespace).Update(new)
}
