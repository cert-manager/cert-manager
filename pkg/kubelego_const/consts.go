package kubelego

import (
	"github.com/xenolf/lego/acme"
	k8sApi "k8s.io/kubernetes/pkg/api"
)

const RsaKeySize = 2048
const AcmeRegistration = "acme-registration.json"
const AcmePrivateKey = k8sApi.TLSPrivateKeyKey
const AcmeKeyType = acme.RSA2048
const AcmeHttpChallengePath = "/.well-known/acme-challenge"
const AcmeHttpSelfTest = "/.well-known/acme-challenge/_selftest"

const TLSCertKey = k8sApi.TLSCertKey
const TLSPrivateKeyKey = k8sApi.TLSPrivateKeyKey
const TLSCaKey = "ca.crt"

const AnnotationIngressChallengeEndpoints = "kubernetes.io/tls-acme-challenge-endpoints"
const AnnotationIngressChallengeEndpointsHash = "kubernetes.io/tls-acme-challenge-endpoints-hash"
const AnnotationEnabled = "kubernetes.io/tls-acme"
