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
	"time"

	"github.com/kr/pretty"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/metrics"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

var (
	certificateGvk = v1alpha1.SchemeGroupVersion.WithKind("Certificate")
)

type calculateDurationUntilRenewFn func(context.Context, *x509.Certificate, *v1alpha1.Certificate) time.Duration

func getCertificateForKey(ctx context.Context, key string, lister cmlisters.CertificateLister) (*v1alpha1.Certificate, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, nil
	}

	crt, err := lister.Certificates(namespace).Get(name)
	if k8sErrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return crt, nil
}

func certificateGetter(lister cmlisters.CertificateLister) func(namespace, name string) (interface{}, error) {
	return func(namespace, name string) (interface{}, error) {
		return lister.Certificates(namespace).Get(name)
	}
}

var keyFunc = controllerpkg.KeyFunc

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
	if apiutil.IssuerKind(crt.Spec.IssuerRef) != secret.Annotations[v1alpha1.IssuerKindAnnotationKey] {
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
