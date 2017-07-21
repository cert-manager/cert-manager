package certificates

import (
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
)

func sync(ctx *controller.Context, crt *v1alpha1.Certificate) error {
	// // step zero: check if the referenced issuer exists and is ready
	// issuer, err := ctx.CertManagerInformerFactory.Certmanager().V1alpha1().Issuers().Lister().Issuers(crt.Namespace).Get(crt.Spec.Issuer)

	// if err != nil {
	// 	return fmt.Errorf("issuer '%s' for certificate '%s' does not exist", crt.Spec.Issuer, crt.Name)
	// }

	// // step one: check if referenced secret exists, if not, trigger issue event
	// secret, err := ctx.InformerFactory.Core().V1().Secrets().Lister().Secrets(crt.Namespace).Get(crt.Spec.SecretName)

	// if err != nil {
	// 	// TODO (@munnerz): only issue a certificate if the call failed due to
	// 	// no resource being found
	// 	return c.issue(crt)
	// }

	// certBytes, okcert := secret.Data[api.TLSCertKey]
	// keyBytes, okkey := secret.Data[api.TLSPrivateKeyKey]

	// // check if the certificate and private key exist, if not, trigger an issue
	// if !okcert || !okkey {
	// 	return c.issue(crt)
	// }
	// // decode the tls certificate pem
	// block, _ := pem.Decode(certBytes)
	// if block == nil {
	// 	ctx.Logger.Printf("error decoding cert PEM block in '%s'", crt.Spec.SecretName)
	// 	return c.issue(crt)
	// }
	// // parse the tls certificate
	// cert, err := x509.ParseCertificate(block.Bytes)
	// if err != nil {
	// 	ctx.Logger.Printf("error parsing TLS certificate in '%s': %s", crt.Spec.SecretName, err.Error())
	// 	return c.issue(crt)
	// }
	// // decode the private key pem
	// block, _ = pem.Decode(keyBytes)
	// if block == nil {
	// 	ctx.Logger.Printf("error decoding private key PEM block in '%s'", crt.Spec.SecretName)
	// 	return c.issue(crt)
	// }
	// // parse the private key
	// key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// if err != nil {
	// 	ctx.Logger.Printf("error parsing private key in '%s': %s", crt.Spec.SecretName, err.Error())
	// 	return c.issue(crt)
	// }
	// // validate the private key
	// if err = key.Validate(); err != nil {
	// 	ctx.Logger.Printf("private key failed validation in '%s': %s", crt.Spec.SecretName, err.Error())
	// 	return c.issue(crt)
	// }
	// // step two: check if referenced secret is valid for listed domains. if not, return failure
	// if !equalUnsorted(crt.Spec.Domains, cert.DNSNames) {
	// 	ctx.Logger.Printf("list of domains on certificate do not match domains in spec")
	// 	return c.issue(crt)
	// }
	// // step three: check if referenced secret is valid (after start & before expiry)
	// if time.Now().Sub(cert.NotAfter) > time.Hour*(24*30) {
	// 	return c.renew(crt)
	// }

	return nil
}

// // issue will attempt to retrieve a certificate from the specified issuer, or
// // return an error on failure. If retrieval is succesful, the certificate data
// // and private key will be stored in the named secret
// func (c *Controller) issue(crt *v1alpha1.Certificate) error {
// 	i, err := issuer.IssuerFor(crt)
// 	if err != nil {
// 		return err
// 	}

// 	cert, key, err := i.Issue(&ctx, crt)
// 	if err != nil {
// 		return fmt.Errorf("error issuing certificate: %s", err.Error())
// 	}

// 	// TODO: support updating resources
// 	_, err = ctx.Client.Secrets(crt.Namespace).Create(&api.Secret{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name:      crt.Spec.SecretName,
// 			Namespace: crt.Namespace,
// 		},
// 		Data: map[string][]byte{
// 			api.TLSCertKey:       cert,
// 			api.TLSPrivateKeyKey: key,
// 		},
// 	})

// 	if err != nil {
// 		return fmt.Errorf("error saving certificate: %s", err.Error())
// 	}

// 	return nil
// }

// // renew will attempt to renew a certificate from the specified issuer, or
// // return an error on failure. If renewal is succesful, the certificate data
// // and private key will be stored in the named secret
// func (c *Controller) renew(crt *v1alpha1.Certificate) error {
// 	i, err := issuer.IssuerFor(crt)
// 	if err != nil {
// 		return err
// 	}

// 	cert, key, err := i.Renew(&ctx, crt)
// 	if err != nil {
// 		return fmt.Errorf("error renewing certificate: %s", err.Error())
// 	}

// 	_, err = ctx.Client.Secrets(crt.Namespace).Update(&api.Secret{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name:      crt.Spec.SecretName,
// 			Namespace: crt.Namespace,
// 		},
// 		Data: map[string][]byte{
// 			api.TLSCertKey:       cert,
// 			api.TLSPrivateKeyKey: key,
// 		},
// 	})

// 	if err != nil {
// 		return fmt.Errorf("error saving certificate: %s", err.Error())
// 	}

// 	return nil
// }

// func equalUnsorted(s1 []string, s2 []string) bool {
// 	if len(s1) != len(s2) {
// 		return false
// 	}
// 	s1_2, s2_2 := make([]string, len(s1)), make([]string, len(s2))
// 	sort.Strings(s1)
// 	sort.Strings(s2)
// 	for i, s := range s1_2 {
// 		if s != s2_2[i] {
// 			return false
// 		}
// 	}
// 	return true
// }
