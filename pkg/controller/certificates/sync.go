package certificates

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/issuer"
	"github.com/jetstack-experimental/cert-manager/pkg/util"
)

const renewBefore = time.Hour * 24 * 30

var errInvalidCertificateData = fmt.Errorf("invalid certificate data")

func (c *Controller) Sync(crt *v1alpha1.Certificate) (err error) {
	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.issuerLister.Issuers(crt.Namespace).Get(crt.Spec.Issuer)

	if err != nil {
		return fmt.Errorf("could not get issuer '%s' for certificate '%s': %s", crt.Spec.Issuer, crt.Name, err.Error())
	}

	if !issuerObj.Status.Ready {
		return fmt.Errorf("issuer '%s/%s' for certificate '%s' not ready", issuerObj.Namespace, issuerObj.Name, crt.Name)
	}

	i, err := c.issuerFactory.IssuerFor(issuerObj)

	if err != nil {
		return fmt.Errorf("error getting issuer implementation for issuer '%s': %s", issuerObj.Name, err.Error())
	}

	// grab existing certificate and validate private key
	cert, _, err := c.getCertificate(crt.Namespace, crt.Spec.SecretName)

	// if an error is returned, and that error is something other than
	// IsNotFound or invalid data, then we should return the error.
	if err != nil && !k8sErrors.IsNotFound(err) && err != errInvalidCertificateData {
		return err
	}

	// as there is an existing certificate, or we may create one below, we will
	// run scheduleRenewal to schedule a renewal if required at the end of
	// execution.
	defer c.scheduleRenewal(crt)

	// if the certificate was not found, or the certificate data is invalid, we
	// should issue a new certificate
	if k8sErrors.IsNotFound(err) || err == errInvalidCertificateData {
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

func (c *Controller) getCertificate(namespace, name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	secret, err := c.client.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})

	if err != nil {
		return nil, nil, err
	}

	certBytes, okcert := secret.Data[api.TLSCertKey]
	keyBytes, okkey := secret.Data[api.TLSPrivateKeyKey]

	// check if the certificate and private key exist, if not, trigger an issue
	if !okcert || !okkey {
		return nil, nil, fmt.Errorf("invalid certificate data")
	}

	// decode the tls certificate pem
	block, _ := pem.Decode(certBytes)
	if block == nil {
		log.Printf("error decoding cert PEM block in '%s/%s'", namespace, name)
		return nil, nil, errInvalidCertificateData
	}
	// parse the tls certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("error parsing TLS certificate in '%s/%s': %s", namespace, name, err.Error())
		return nil, nil, errInvalidCertificateData
	}
	// decode the private key pem
	block, _ = pem.Decode(keyBytes)
	if block == nil {
		log.Printf("error decoding private key PEM block in '%s/%s'", namespace, name)
		return nil, nil, errInvalidCertificateData
	}
	// parse the private key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("error parsing private key in '%s/%s': %s", namespace, name, err.Error())
		return nil, nil, errInvalidCertificateData
	}
	// validate the private key
	if err = key.Validate(); err != nil {
		log.Printf("private key failed validation in '%s/%s': %s", namespace, name, err.Error())
		return nil, nil, errInvalidCertificateData
	}
	return cert, key, nil
}

func (c *Controller) scheduleRenewal(crt *v1alpha1.Certificate) {
	key, err := keyFunc(crt)

	if err != nil {
		runtime.HandleError(fmt.Errorf("error getting key for certificate resource: %s", err.Error()))
		return
	}

	cert, _, err := c.getCertificate(crt.Namespace, crt.Spec.SecretName)

	if err != nil {
		runtime.HandleError(fmt.Errorf("[%s/%s] Error getting certificate '%s': %s", crt.Namespace, crt.Name, crt.Spec.SecretName, err.Error()))
		return
	}

	durationUntilExpiry := cert.NotAfter.Sub(time.Now())
	renewIn := durationUntilExpiry - renewBefore
	log.Printf("[%s/%s] Scheduling renewal in %d hours", crt.Namespace, crt.Name, renewIn/time.Hour)
	c.scheduledWorkQueue.Add(key, renewIn)
}

func (c *Controller) prepare(issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	log.Printf("Preparing Certificate '%s/%s'", crt.Namespace, crt.Name)
	err := issuer.Prepare(crt)

	if err != nil {
		return err
	}

	log.Printf("Finished preparing Certificate '%s/%s'", crt.Namespace, crt.Name)
	return nil
}

// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) issue(issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	if err := c.prepare(issuer, crt); err != nil {
		return err
	}

	log.Printf("[%s/%s] Issuing certificate...", crt.Namespace, crt.Name)
	key, cert, err := issuer.Issue(crt)
	if err != nil {
		return fmt.Errorf("error issuing certificate: %s", err.Error())
	}

	_, err = util.EnsureSecret(c.client, &api.Secret{
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
		return fmt.Errorf("error saving certificate: %s", err.Error())
	}

	log.Printf("[%s/%s] Successfully issued certificate (%s)", crt.Namespace, crt.Name, crt.Spec.SecretName)

	return nil
}

// renew will attempt to renew a certificate from the specified issuer, or
// return an error on failure. If renewal is succesful, the certificate data
// and private key will be stored in the named secret
func (c *Controller) renew(issuer issuer.Interface, crt *v1alpha1.Certificate) error {
	if err := c.prepare(issuer, crt); err != nil {
		return err
	}

	log.Printf("[%s/%s] Renewing certificate...", crt.Namespace, crt.Name)
	key, cert, err := issuer.Renew(crt)
	if err != nil {
		return fmt.Errorf("error renewing certificate: %s", err.Error())
	}

	_, err = util.EnsureSecret(c.client, &api.Secret{
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
		return fmt.Errorf("error saving certificate: %s", err.Error())
	}

	log.Printf("[%s/%s] Successfully renewed certificate (%s)", crt.Namespace, crt.Name, crt.Spec.SecretName)

	return nil
}
