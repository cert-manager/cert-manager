package util

import (
	"crypto/x509"
	"flag"
	"fmt"
	"time"

	"github.com/golang/glog"
	intscheme "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/scheme"
	"k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
)

var ACMECertificateDomain string
var ACMECloudflareDomain string

func init() {
	flag.StringVar(&ACMECertificateDomain, "acme-nginx-certificate-domain", "",
		"The provided domain and all sub-domains should resolve to the nginx ingress controller")
	flag.StringVar(&ACMECloudflareDomain, "acme-cloudflare-domain", "",
		"A domain name manageable using the test cloudflare api token to be used for testing "+
			"the DNS01 provider")
}

func CertificateOnlyValidForDomains(cert *x509.Certificate, commonName string, dnsNames ...string) bool {
	if commonName != cert.Subject.CommonName || !util.EqualUnsorted(cert.DNSNames, dnsNames) {
		return false
	}
	return true
}

func WaitForIssuerStatusFunc(client clientset.IssuerInterface, name string, fn func(*v1alpha1.Issuer) (bool, error)) error {
	return wait.PollImmediate(500*time.Millisecond, wait.ForeverTestTimeout,
		func() (bool, error) {
			issuer, err := client.Get(name, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}
			return fn(issuer)
		})
}

// WaitForIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func WaitForIssuerCondition(client clientset.IssuerInterface, name string, condition v1alpha1.IssuerCondition) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, wait.ForeverTestTimeout,
		func() (bool, error) {
			glog.V(5).Infof("Waiting for issuer %v condition %#v", name, condition)
			issuer, err := client.Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Issuer %q: %v", name, err)
			}

			return issuer.HasCondition(condition), nil
		},
	)
	return wrapErrorWithIssuerStatusCondition(client, pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithIssuerStatusCondition(client clientset.IssuerInterface, pollErr error, name string, conditionType v1alpha1.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	issuer, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		return pollErr
	}

	for _, cond := range issuer.GetStatus().Conditions {
		if cond.Type == conditionType {
			return fmt.Errorf("%s: Last Status: '%s' Reason: '%s', Message: '%s'", pollErr.Error(), cond.Status, cond.Reason, cond.Message)
		}

	}

	return pollErr
}

// WaitForClusterIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func WaitForClusterIssuerCondition(client clientset.ClusterIssuerInterface, name string, condition v1alpha1.IssuerCondition) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, wait.ForeverTestTimeout,
		func() (bool, error) {
			glog.V(5).Infof("Waiting for clusterissuer %v condition %#v", name, condition)
			issuer, err := client.Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting ClusterIssuer %v: %v", name, err)
			}

			return issuer.HasCondition(condition), nil
		},
	)
	return wrapErrorWithClusterIssuerStatusCondition(client, pollErr, name, condition.Type)
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithClusterIssuerStatusCondition(client clientset.ClusterIssuerInterface, pollErr error, name string, conditionType v1alpha1.IssuerConditionType) error {
	if pollErr == nil {
		return nil
	}

	issuer, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		return pollErr
	}

	for _, cond := range issuer.GetStatus().Conditions {
		if cond.Type == conditionType {
			return fmt.Errorf("%s: Last Status: '%s' Reason: '%s', Message: '%s'", pollErr.Error(), cond.Status, cond.Reason, cond.Message)
		}

	}

	return pollErr
}

// WaitForCertificateCondition waits for the status of the named Certificate to contain
// a condition whose type and status matches the supplied one.
func WaitForCertificateCondition(client clientset.CertificateInterface, name string, condition v1alpha1.CertificateCondition, timeout time.Duration) error {
	pollErr := wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			glog.V(5).Infof("Waiting for Certificate %v condition %#v", name, condition)
			certificate, err := client.Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}

			return certificate.HasCondition(condition), nil
		},
	)
	return wrapErrorWithCertificateStatusCondition(client, pollErr, name, condition.Type)
}

// WaitForCertificateEvent waits for an event on the named Certificate to contain
// an event reason matches the supplied one.
func WaitForCertificateEvent(client kubernetes.Interface, cert *v1alpha1.Certificate, reason string, timeout time.Duration) error {
	return wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			glog.V(5).Infof("Waiting for Certificate event %v reason %#v", cert.Name, reason)
			evts, err := client.Core().Events(cert.Namespace).Search(intscheme.Scheme, cert)
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", cert.Name, err)
			}

			return hasEvent(evts, reason), nil
		},
	)
}

func hasEvent(events *v1.EventList, reason string) bool {
	for _, evt := range events.Items {
		if evt.Reason == reason {
			return true
		}
	}
	return false
}

// try to retrieve last condition to help diagnose tests.
func wrapErrorWithCertificateStatusCondition(client clientset.CertificateInterface, pollErr error, name string, conditionType v1alpha1.CertificateConditionType) error {
	if pollErr == nil {
		return nil
	}

	certificate, err := client.Get(name, metav1.GetOptions{})
	if err != nil {
		return pollErr
	}

	for _, cond := range certificate.Status.Conditions {
		if cond.Type == conditionType {
			return fmt.Errorf("%s: Last Status: '%s' Reason: '%s', Message: '%s'", pollErr.Error(), cond.Status, cond.Reason, cond.Message)
		}
	}

	return pollErr
}

// WaitForCertificateToExist waits for the named certificate to exist
func WaitForCertificateToExist(client clientset.CertificateInterface, name string, timeout time.Duration) error {
	return wait.PollImmediate(500*time.Millisecond, timeout,
		func() (bool, error) {
			glog.V(5).Infof("Waiting for Certificate %v to exist", name)
			_, err := client.Get(name, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, fmt.Errorf("error getting Certificate %v: %v", name, err)
			}

			return true, nil
		},
	)
}

// WaitForCRDToNotExist waits for the CRD with the given name to no
// longer exist.
func WaitForCRDToNotExist(client apiextcs.CustomResourceDefinitionInterface, name string) error {
	return wait.PollImmediate(500*time.Millisecond, wait.ForeverTestTimeout,
		func() (bool, error) {
			glog.V(5).Infof("Waiting for CRD %v to not exist", name)
			_, err := client.Get(name, metav1.GetOptions{})
			if nil == err {
				return false, nil
			}

			if errors.IsNotFound(err) {
				return true, nil
			}

			return false, nil
		},
	)
}

func NewCertManagerCAClusterIssuer(name, secretName string) *v1alpha1.ClusterIssuer {
	return &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				CA: &v1alpha1.CAIssuer{
					SecretName: secretName,
				},
			},
		},
	}
}

func NewCertManagerCACertificate(name, secretName, issuerName string, issuerKind string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.CertificateSpec{
			CommonName: "test.domain.com",
			SecretName: secretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
}

func NewCertManagerACMECertificate(name, secretName, issuerName string, issuerKind string, ingressClass string, cn string, dnsNames ...string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.CertificateSpec{
			CommonName: cn,
			DNSNames:   dnsNames,
			SecretName: secretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
			ACME: &v1alpha1.ACMECertificateConfig{
				Config: []v1alpha1.ACMECertificateDomainConfig{
					{
						Domains: append(dnsNames, cn),
						ACMESolverConfig: v1alpha1.ACMESolverConfig{
							HTTP01: &v1alpha1.ACMECertificateHTTP01Config{
								IngressClass: &ingressClass,
							},
						},
					},
				},
			},
		},
	}
}

func NewCertManagerVaultCertificate(name, secretName, issuerName string, issuerKind string) *v1alpha1.Certificate {
	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.CertificateSpec{
			CommonName: "test.domain.com",
			SecretName: secretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
}

func NewIngress(name, secretName string, annotations map[string]string, dnsNames ...string) *extv1beta1.Ingress {
	return &extv1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: extv1beta1.IngressSpec{
			TLS: []extv1beta1.IngressTLS{
				{
					Hosts:      dnsNames,
					SecretName: secretName,
				},
			},
			Rules: []extv1beta1.IngressRule{
				{
					Host: dnsNames[0],
					IngressRuleValue: extv1beta1.IngressRuleValue{
						HTTP: &extv1beta1.HTTPIngressRuleValue{
							Paths: []extv1beta1.HTTPIngressPath{
								{
									Path: "/",
									Backend: extv1beta1.IngressBackend{
										ServiceName: "dummy-service",
										ServicePort: intstr.FromInt(80),
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func NewCertManagerACMEIssuer(name, acmeURL, acmeEmail, acmePrivateKey string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				ACME: &v1alpha1.ACMEIssuer{
					Email:         acmeEmail,
					Server:        acmeURL,
					SkipTLSVerify: true,
					PrivateKey: v1alpha1.SecretKeySelector{
						LocalObjectReference: v1alpha1.LocalObjectReference{
							Name: acmePrivateKey,
						},
					},
					HTTP01: &v1alpha1.ACMEIssuerHTTP01Config{},
				},
			},
		},
	}
}

func NewCertManagerCAIssuer(name, secretName string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				CA: &v1alpha1.CAIssuer{
					SecretName: secretName,
				},
			},
		},
	}
}

func NewCertManagerVaultIssuerToken(name, vaultURL, vaultPath, vaultSecretToken string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				Vault: &v1alpha1.VaultIssuer{
					Server: vaultURL,
					Path:   vaultPath,
					Auth: v1alpha1.VaultAuth{
						TokenSecretRef: v1alpha1.SecretKeySelector{
							Key: "secretkey",
							LocalObjectReference: v1alpha1.LocalObjectReference{
								Name: vaultSecretToken,
							},
						},
					},
				},
			},
		},
	}
}

func NewCertManagerVaultIssuerAppRole(name, vaultURL, vaultPath, roleId, vaultSecretAppRole string) *v1alpha1.Issuer {
	return &v1alpha1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				Vault: &v1alpha1.VaultIssuer{
					Server: vaultURL,
					Path:   vaultPath,
					Auth: v1alpha1.VaultAuth{
						AppRole: v1alpha1.VaultAppRole{
							RoleId: roleId,
							SecretRef: v1alpha1.SecretKeySelector{
								Key: "secretkey",
								LocalObjectReference: v1alpha1.LocalObjectReference{
									Name: vaultSecretAppRole,
								},
							},
						},
					},
				},
			},
		},
	}
}

func NewSigningKeypairSecret(name string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			v1.TLSCertKey: `-----BEGIN CERTIFICATE-----
MIID4DCCAsigAwIBAgIJAJzTROInmDkQMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNV
BAYTAlVLMQswCQYDVQQIEwJOQTEVMBMGA1UEChMMY2VydC1tYW5hZ2VyMSAwHgYD
VQQDExdjZXJ0LW1hbmFnZXIgdGVzdGluZyBDQTAeFw0xNzA5MTAxODMzNDNaFw0y
NzA5MDgxODMzNDNaMFMxCzAJBgNVBAYTAlVLMQswCQYDVQQIEwJOQTEVMBMGA1UE
ChMMY2VydC1tYW5hZ2VyMSAwHgYDVQQDExdjZXJ0LW1hbmFnZXIgdGVzdGluZyBD
QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM+Q2AO4hARav0qwjk7I
4mEh5R201HS8s7HpaLOXBNvvh7qJ9yJz6jLqYg6EvP0K/bK56Cp2oe2igd7GOxpV
3YPOc3CG0CCqHMprEcvxj2xBKX00Rtcn4oVLhDPhAb0BV/R7NFLeWxzh+ggvPI1X
m1qLaWYqYZEJ5bBsYXD3tPdS4GGINRz8Zvih46f0Z2wVkCGoTpsbX8HO74sa2Day
UjzAsWGlO5bZGiMSHjDEnf9yek2TcjEyVoohoOLaQg/ng21T5RWzeZKTl1cznwuG
Vr9tZfHFqxQ5qeaId+1ICtxNvkEjbTnZl6Wy9Cthn0dxwOeS5TqMJ7SFNXy1gp4j
f/MCAwEAAaOBtjCBszAdBgNVHQ4EFgQUBtrjvWfbkLA0iX6sKVRhKUo864kwgYMG
A1UdIwR8MHqAFAba471n25CwNIl+rClUYSlKPOuJoVekVTBTMQswCQYDVQQGEwJV
SzELMAkGA1UECBMCTkExFTATBgNVBAoTDGNlcnQtbWFuYWdlcjEgMB4GA1UEAxMX
Y2VydC1tYW5hZ2VyIHRlc3RpbmcgQ0GCCQCc00TiJ5g5EDAMBgNVHRMEBTADAQH/
MA0GCSqGSIb3DQEBCwUAA4IBAQCR+jXhup5tCKwhAf8xgvp589BczQOjmotuZGEL
Dcint2y263ChEdsoLhyJfvFCAZfTSm+UT95Hl+ZKVuoVEcAS7udaFUFpC/gIYVOi
H4/uvJps4SpVCB7+T/orcTjZ2ewT23mQAQg+B+iwX9VCof+fadkYOg1XD9/eaj6E
9McXID3iuCXg02RmEOwVMrTggHPwHrOGAilSaZc58cJZHmMYlT5rGrJcWS/AyXnH
VOodKC004yjh7w9aSbCCbAL0tDEnhm4Jrb8cxt7pDWbdEVUeuk9LZRQtluYBnmJU
kQ7ALfUfUh/RUpCV4uI6sEI3NDX2YqQbOtsBD/hNaL1F85FA
-----END CERTIFICATE-----`,
			v1.TLSPrivateKeyKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz5DYA7iEBFq/SrCOTsjiYSHlHbTUdLyzselos5cE2++Huon3
InPqMupiDoS8/Qr9srnoKnah7aKB3sY7GlXdg85zcIbQIKocymsRy/GPbEEpfTRG
1yfihUuEM+EBvQFX9Hs0Ut5bHOH6CC88jVebWotpZiphkQnlsGxhcPe091LgYYg1
HPxm+KHjp/RnbBWQIahOmxtfwc7vixrYNrJSPMCxYaU7ltkaIxIeMMSd/3J6TZNy
MTJWiiGg4tpCD+eDbVPlFbN5kpOXVzOfC4ZWv21l8cWrFDmp5oh37UgK3E2+QSNt
OdmXpbL0K2GfR3HA55LlOowntIU1fLWCniN/8wIDAQABAoIBAQCYvGvIKSG0FpbG
vi6pmLbEZO20s1jW4fiUxT2PUWR49sR4pocdahB/EOvA5TowNcNDnftSK+Ox+q/4
HwRkt6R+Fg/qULmcH7F53dnFqeYw8a42/J3YOvg7v7rzdfISg4eWVobFJ+wBz+Nt
3FyBYWLm+MlBLZSH5rGG5em59/zJNHWIhH+oQPfCxAkYEvd8tXOTUzjhqvEfjaJy
FZghnT9xto4MwDdNCPbtzdNjTMhiv0AHkcZGGtRJfkehXX2qhXOQ2UzzO9XrMZnv
5KgYf+bXKJsyS3SPl6TTl7vg2gKBciRvsdFhMy5I5GyIADrEDJnNNmXQRtiaFLfd
k/aqfPT5AoGBAPquMouZUbVS/Qh+qbls7G4zAuznfCiqdctcKmUGPRP4sTTjWdUp
fjI+UTt1e8hncmr4RY7Oa9kUV/kDwzS5spUZZ+u0PczS3XKxOwNOleoH00dfc9vt
cxctHdPdDTndRi8Z4k3m931jIX7jB/Pyx8qeNYB3pj0k3ThktwMbAVLnAoGBANP4
beI5zpbvtAdExJcuxx2mRDGF0lIdKC0bvQaeqM3Lwqnmc0Fz1dbP7KXDa+SdJWPd
res+NHPZoEPeEJuDTSngXOLNECZe4Ja9frn1TeY858vMJBwIkyc8zu+sgXxjQUM+
TWUlTUhtXyybkRnxAEny4OT2TTgmXITJaKOmV1UVAoGAHaXSlo4YitB42rNYUXTf
dZ0U4H30Qj7+1YFeBjq5qI4GL1IgQsS4hyq1osmfTTFm593bJCunt7HfQbU/NhIs
W9P4ZXkYwgvCYxkw+JAnzNkGFO/mHQG1Ve1hFLiVIt3XuiRejoYdiTfbM02YmDKD
jKQvgbUk9SBSBaRrvLNJ8csCgYAYnrZEnGo+ZcEHRxl+ZdSCwRkSl3SCTRiphJtD
9ZGttYj6quWgKJAhzyyxZC1X9FivbMQSmrsE6bYPq+9J4MpJnuGrBh5mFocHeyMI
/lD5+QEDTsay6twMpqdydxrjE7Q01zuuD9MWIn33dGo6FR/vduJgNatqZipA0hPx
ThS+sQKBgQDh0+cVo1mfYiCkp3IQPB8QYiJ/g2/UBk6pH8ZZDZ+A5td6NveiWO1y
wTEUWkX2qyz9SLxWDGOhdKqxNrLCUSYSOV/5/JQEtBm6K50ArFtrY40JP/T/5KvM
tSK2ayFX1wQ3PuEmewAogy/20tWo80cr556AXA62Utl2PzLK30Db8w==
-----END RSA PRIVATE KEY-----`,
		},
	}
}
