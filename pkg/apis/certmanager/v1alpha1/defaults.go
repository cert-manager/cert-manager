package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

func SetDefaults_ACMEIssuer(acmeIssuer *ACMEIssuer) {
	if acmeIssuer.PrivateKey.Key == "" {
		acmeIssuer.PrivateKey.Key = corev1.TLSPrivateKeyKey
	}
}
