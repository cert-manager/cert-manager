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
	"hash/fnv"
	"math/big"
	"reflect"
	"sort"
	"time"

	"github.com/kr/pretty"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/kube"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

var (
	certificateGvk = cmapi.SchemeGroupVersion.WithKind("Certificate")
)

type calculateDurationUntilRenewFn func(context.Context, *x509.Certificate, *cmapi.Certificate) time.Duration

func getCertificateForKey(ctx context.Context, key string, lister cmlisters.CertificateLister) (*cmapi.Certificate, error) {
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

func certificateMatchesSpec(crt *cmapi.Certificate, key crypto.Signer, cert *x509.Certificate, secret *corev1.Secret) (bool, []string) {
	var errs []string

	// check if the private key is the corresponding pair to the certificate

	matches, err := pki.PublicKeyMatchesCertificate(key.Public(), cert)
	if err != nil {
		errs = append(errs, err.Error())
	} else if !matches {
		errs = append(errs, fmt.Sprintf("Certificate private key does not match certificate"))
	}

	// If CN is set on the resource then it should exist on the certificate as
	// the Common Name or a DNS Name
	expectedCN := crt.Spec.CommonName
	gotCN := append(cert.DNSNames, cert.Subject.CommonName)
	if len(expectedCN) > 0 && !util.Contains(gotCN, expectedCN) {
		errs = append(errs, fmt.Sprintf("Common Name on TLS certificate not up to date (%q): %s",
			expectedCN, gotCN))
	}

	// validate the dns names are correct
	expectedDNSNames := crt.Spec.DNSNames
	if !util.Subset(cert.DNSNames, expectedDNSNames) {
		errs = append(errs, fmt.Sprintf("DNS names on TLS certificate not up to date: %q", cert.DNSNames))
	}

	expectedURIs := crt.Spec.URISANs
	if !util.EqualUnsorted(pki.URLsToString(cert.URIs), expectedURIs) {
		errs = append(errs, fmt.Sprintf("URI SANs on TLS certificate not up to date: %q", cert.URIs))
	}

	// validate the ip addresses are correct
	if !util.EqualUnsorted(pki.IPAddressesToString(cert.IPAddresses), crt.Spec.IPAddresses) {
		errs = append(errs, fmt.Sprintf("IP addresses on TLS certificate not up to date: %q", pki.IPAddressesToString(cert.IPAddresses)))
	}

	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}

	// Validate that the issuer name and kind is correct
	// If the new annotation exists and doesn't match then error
	// If the new annotation doesn't exist and the old annotation doesn't match then error

	annotationError := func(k, v string) {
		errs = append(errs, fmt.Sprintf("Issuer %q of the certificate is not up to date: %q", k, v))
	}

	name, ok := secret.Annotations[cmapi.IssuerNameAnnotationKey]
	if !ok {
		if secret.Annotations[cmapi.DeprecatedIssuerNameAnnotationKey] != crt.Spec.IssuerRef.Name {
			annotationError(cmapi.DeprecatedIssuerNameAnnotationKey, secret.Annotations[cmapi.DeprecatedIssuerNameAnnotationKey])
		}
	} else if name != crt.Spec.IssuerRef.Name {
		annotationError(cmapi.IssuerNameAnnotationKey, secret.Annotations[cmapi.IssuerNameAnnotationKey])
	}

	kind, ok := secret.Annotations[cmapi.IssuerKindAnnotationKey]
	if !ok {
		if secret.Annotations[cmapi.DeprecatedIssuerKindAnnotationKey] != apiutil.IssuerKind(crt.Spec.IssuerRef) {
			annotationError(cmapi.DeprecatedIssuerKindAnnotationKey, secret.Annotations[cmapi.DeprecatedIssuerKindAnnotationKey])
		}
	} else if kind != apiutil.IssuerKind(crt.Spec.IssuerRef) {
		annotationError(cmapi.IssuerKindAnnotationKey, secret.Annotations[cmapi.IssuerKindAnnotationKey])
	}

	return len(errs) == 0, errs
}

func certificateSpecMatchesCertificateRequest(crt *cmapi.Certificate, cr *cmapi.CertificateRequest, secret *corev1.Secret) (bool, error) {
	crtCopy := crt.DeepCopy()
	crCopy := cr.DeepCopy()

	csr, err := pki.DecodeX509CertificateRequestBytes(crCopy.Spec.CSRPEM)
	if err != nil {
		return false, err
	}

	trimmedSpecFromCRHash, err := hashCertificateSpec(trimmedCertificateSpecFromCSR(csr))
	if err != nil {
		return false, err
	}

	trimmedSpecFromCertificate, err := hashCertificateSpec(trimmedCertificateSpecFromCertificate(crtCopy))
	if err != nil {
		return false, err
	}

	if trimmedSpecFromCRHash != trimmedSpecFromCertificate {
		return false, nil
	}

	if len(crCopy.Spec.Usages) != len(crtCopy.Spec.Usages) {
		return false, nil
	}

	sort.SliceStable(crCopy.Spec.Usages, func(i, j int) bool { return crCopy.Spec.Usages[i] < crCopy.Spec.Usages[j] })
	sort.SliceStable(crtCopy.Spec.Usages, func(i, j int) bool { return crtCopy.Spec.Usages[i] < crtCopy.Spec.Usages[j] })

	for i, s := range crCopy.Spec.Usages {
		if s != crtCopy.Spec.Usages[i] {
			return false, nil
		}
	}

	if crCopy.Spec.IsCA != crt.Spec.IsCA {
		return false, nil
	}

	if crCopy.Spec.Duration.String() != crt.Spec.Duration.String() {
		return false, nil
	}

	return true, nil
}

func trimmedCertificateSpecFromCSR(csr *x509.CertificateRequest) *cmapi.CertificateSpec {
	var ips []string
	for _, ip := range csr.IPAddresses {
		ips = append(ips, ip.String())
	}

	var uris []string
	for _, uri := range csr.URIs {
		uris = append(uris, uri.String())
	}

	for _, s := range [][]string{
		csr.DNSNames,
		csr.Subject.Organization,
		ips,
		uris,
		csr.Subject.Country,
		csr.Subject.OrganizationalUnit,
		csr.Subject.Locality,
		csr.Subject.Province,
		csr.Subject.StreetAddress,
		csr.Subject.PostalCode,
	} {
		sort.Strings(s)
	}

	return &cmapi.CertificateSpec{
		CommonName:   csr.Subject.CommonName,
		DNSNames:     csr.DNSNames,
		IPAddresses:  ips,
		Organization: csr.Subject.Organization,
		Subject: &cmapi.X509Subject{
			Countries:           csr.Subject.Country,
			OrganizationalUnits: csr.Subject.OrganizationalUnit,
			Localities:          csr.Subject.Locality,
			Provinces:           csr.Subject.Province,
			StreetAddresses:     csr.Subject.StreetAddress,
			PostalCodes:         csr.Subject.PostalCode,
			SerialNumber:        csr.Subject.SerialNumber,
		},
		URISANs: uris,
	}
}

func trimmedCertificateSpecFromCertificate(crt *cmapi.Certificate) *cmapi.CertificateSpec {
	spec := crt.DeepCopy().Spec

	if spec.Subject == nil {
		spec.Subject = new(cmapi.X509Subject)
	}

	spec.Organization = pki.OrganizationForCertificate(crt)

	for _, s := range [][]string{
		spec.DNSNames,
		spec.Organization,
		spec.IPAddresses,
		spec.Subject.Countries,
		spec.Subject.OrganizationalUnits,
		spec.Subject.Localities,
		spec.Subject.Provinces,
		spec.Subject.StreetAddresses,
		spec.Subject.PostalCodes,
		spec.URISANs,
	} {
		sort.Strings(s)
	}

	return &cmapi.CertificateSpec{
		CommonName:   spec.CommonName,
		DNSNames:     spec.DNSNames,
		IPAddresses:  spec.IPAddresses,
		Organization: spec.Organization,
		Subject: &cmapi.X509Subject{
			Countries:           spec.Subject.Countries,
			OrganizationalUnits: spec.Subject.OrganizationalUnits,
			Localities:          spec.Subject.Localities,
			Provinces:           spec.Subject.Provinces,
			StreetAddresses:     spec.Subject.StreetAddresses,
			PostalCodes:         spec.Subject.PostalCodes,
			SerialNumber:        spec.Subject.SerialNumber,
		},
		URISANs: spec.URISANs,
	}
}

func hashCertificateSpec(spec *cmapi.CertificateSpec) (uint32, error) {
	specBytes, err := json.Marshal(spec)
	if err != nil {
		return 0, err
	}

	hashF := fnv.New32()
	_, err = hashF.Write(specBytes)
	if err != nil {
		return 0, err
	}

	return hashF.Sum32(), nil
}

func scheduleRenewal(ctx context.Context, lister corelisters.SecretLister, calc calculateDurationUntilRenewFn, queueFn func(interface{}, time.Duration), crt *cmapi.Certificate) {
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
func generateLocallySignedTemporaryCertificate(crt *cmapi.Certificate, pk []byte) ([]byte, error) {
	// generate a throwaway self-signed root CA
	caPk, err := pki.GenerateECPrivateKey(pki.ECCurve521)
	if err != nil {
		return nil, err
	}
	caCertTemplate, err := pki.GenerateTemplate(&cmapi.Certificate{
		Spec: cmapi.CertificateSpec{
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

func updateCertificateStatus(ctx context.Context, cmClient cmclient.Interface, old, new *cmapi.Certificate) (*cmapi.Certificate, error) {
	log := logf.FromContext(ctx, "updateStatus")
	oldBytes, _ := json.Marshal(old.Status)
	newBytes, _ := json.Marshal(new.Status)
	if reflect.DeepEqual(oldBytes, newBytes) {
		return nil, nil
	}
	log.V(logf.DebugLevel).Info("updating resource due to change in status", "diff", pretty.Diff(string(oldBytes), string(newBytes)))
	return cmClient.CertmanagerV1alpha2().Certificates(new.Namespace).UpdateStatus(new)
}

func certificateHasTemporaryCertificateAnnotation(crt *cmapi.Certificate) bool {
	if crt.Annotations == nil {
		return false
	}

	if val, ok := crt.Annotations[cmapi.IssueTemporaryCertificateAnnotation]; ok && val == "true" {
		return true
	}

	return false
}
