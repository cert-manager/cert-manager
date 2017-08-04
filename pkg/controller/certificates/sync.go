package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	api "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/munnerz/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/munnerz/cert-manager/pkg/issuer"
	"github.com/munnerz/cert-manager/pkg/util"
)

func (c *controller) sync(crt *v1alpha1.Certificate) error {
	// step zero: check if the referenced issuer exists and is ready
	issuerObj, err := c.issuerLister.Issuers(crt.Namespace).Get(crt.Spec.Issuer)

	if err != nil {
		return fmt.Errorf("could not get issuer '%s' for certificate '%s': %s", crt.Spec.Issuer, crt.Name, err.Error())
	}

	if !issuerObj.Status.Ready {
		return fmt.Errorf("issuer '%s/%s' for certificate '%s' not ready", issuerObj.Namespace, issuerObj.Name, crt.Name)
	}

	i, err := issuer.SharedFactory().IssuerFor(issuerObj)

	if err != nil {
		return fmt.Errorf("error getting issuer implementation for issuer '%s': %s", issuerObj.Name, err.Error())
	}

	// TODO: move this to after the certificate check to avoid unneeded authorization checks
	err = i.Prepare(crt)

	if err != nil {
		return err
	}

	// step one: check if referenced secret exists, if not, trigger issue event
	secret, err := c.secretLister.Secrets(crt.Namespace).Get(crt.Spec.SecretName)

	if err != nil {
		if k8sErrors.IsNotFound(err) {
			return c.issue(i, crt)
		}
		return err
	}

	certBytes, okcert := secret.Data[api.TLSCertKey]
	keyBytes, okkey := secret.Data[api.TLSPrivateKeyKey]

	// check if the certificate and private key exist, if not, trigger an issue
	if !okcert || !okkey {
		return c.issue(i, crt)
	}
	// decode the tls certificate pem
	block, _ := pem.Decode(certBytes)
	if block == nil {
		log.Printf("error decoding cert PEM block in '%s'", crt.Spec.SecretName)
		return c.issue(i, crt)
	}
	// parse the tls certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("error parsing TLS certificate in '%s': %s", crt.Spec.SecretName, err.Error())
		return c.issue(i, crt)
	}
	// decode the private key pem
	block, _ = pem.Decode(keyBytes)
	if block == nil {
		log.Printf("error decoding private key PEM block in '%s'", crt.Spec.SecretName)
		return c.issue(i, crt)
	}
	// parse the private key
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("error parsing private key in '%s': %s", crt.Spec.SecretName, err.Error())
		return c.issue(i, crt)
	}
	// validate the private key
	if err = key.Validate(); err != nil {
		log.Printf("private key failed validation in '%s': %s", crt.Spec.SecretName, err.Error())
		return c.issue(i, crt)
	}
	// step two: check if referenced secret is valid for listed domains. if not, return failure
	if !util.EqualUnsorted(crt.Spec.Domains, cert.DNSNames) {
		log.Printf("list of domains on certificate do not match domains in spec")
		return c.issue(i, crt)
	}
	// step three: check if referenced secret is valid (after start & before expiry)
	// if time.Now().Sub(cert.NotAfter) > time.Hour*(24*30) {
	// 	return c.renew(crt)
	// }

	return nil
}

// issue will attempt to retrieve a certificate from the specified issuer, or
// return an error on failure. If retrieval is succesful, the certificate data
// and private key will be stored in the named secret
func (c *controller) issue(issuer issuer.Interface, crt *v1alpha1.Certificate) error {
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

	return nil
}

// renew will attempt to renew a certificate from the specified issuer, or
// return an error on failure. If renewal is succesful, the certificate data
// and private key will be stored in the named secret
func (c *controller) renew(issuer issuer.Interface, crt *v1alpha1.Certificate) error {
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

	return nil
}
