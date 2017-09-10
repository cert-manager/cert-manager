package kube

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/jetstack-experimental/cert-manager/pkg/util/errors"
	"github.com/jetstack-experimental/cert-manager/pkg/util/pki"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
)

func GetKeyPair(cl kubernetes.Interface, namespace, name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	secret, err := cl.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})

	if err != nil {
		return nil, nil, err
	}

	certBytes, okcert := secret.Data[api.TLSCertKey]
	keyBytes, okkey := secret.Data[api.TLSPrivateKeyKey]

	// check if the certificate and private key exist, we stop so as to not
	// destroy a secret potentially used for something else
	if !okcert || !okkey {
		return nil, nil, fmt.Errorf("Secret does not contain TLS fields")
	}

	key, keyErr := pki.DecodePKCS1PrivateKeyBytes(keyBytes)
	cert, certErr := pki.DecodeX509CertificateBytes(certBytes)

	var errs []error
	if keyErr != nil {
		errs = append(errs, keyErr)
	}
	if certErr != nil {
		errs = append(errs, certErr)
	}
	if len(errs) > 0 {
		err = errors.NewInvalidData(utilerrors.NewAggregate(errs).Error())
	}

	return cert, key, err
}
