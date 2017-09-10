package ca

import (
	"fmt"

	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack-experimental/cert-manager/pkg/util/kube"
	"github.com/jetstack-experimental/cert-manager/pkg/util/pki"
)

func (c *CA) Renew(crt *v1alpha1.Certificate) ([]byte, []byte, error) {
	signerCert, signerKey, err := kube.GetKeyPair(c.cl, c.issuer.Namespace, c.issuer.Spec.CA.SecretRef.Name)

	if err != nil {
		return nil, nil, err
	}

	_, signeeKey, err := kube.GetKeyPair(c.cl, crt.Namespace, crt.Spec.SecretName)

	if signeeKey == nil {
		return nil, nil, fmt.Errorf("error getting certificate private key: %s", err.Error())
	}

	crtPem, _, err := signCertificate(crt, signerCert, &signeeKey.PublicKey, signerKey)

	if err != nil {
		return nil, nil, err
	}

	return pki.EncodePKCS1PrivateKey(signeeKey), crtPem, nil
}
