package util

import "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"

func GetSecretsNamespace(crt *v1alpha2.Certificate) string {
	namespace, ok := crt.Annotations[v1alpha2.SecretsNamespaceAnnotationKey]

	if !ok {
		return crt.Namespace
	}

	return namespace
}
