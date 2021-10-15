package v1beta1

import (
	certmanager "github.com/cert-manager/cert-manager/internal/apis/certmanager"
	conversion "k8s.io/apimachinery/pkg/conversion"
)

func Convert_certmanager_VaultKubernetesAuth_To_v1beta1_VaultKubernetesAuth(in *certmanager.VaultKubernetesAuth, out *VaultKubernetesAuth, s conversion.Scope) error {
	return autoConvert_certmanager_VaultKubernetesAuth_To_v1beta1_VaultKubernetesAuth(in, out, s)
}
