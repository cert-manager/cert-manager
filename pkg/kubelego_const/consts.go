package kubelego

import (
	"github.com/xenolf/lego/acme"
)

const RsaKeySize = 2048
const TLSRegistration = "registration.json"
const AcmeKeyType = acme.RSA2048
const AcmeHttpChallengePath = "/.well-known/acme-challenge/"

const AnnotationIngressChallengeEndpoints = "kubernetes.io/tls-acme-challenge-endpoints"
const AnnotationIngressChallengeEndpointsHash = "kubernetes.io/tls-acme-challenge-endpoints-hash"
const AnnotationEnabled = "kubernetes.io/tls-acme"
