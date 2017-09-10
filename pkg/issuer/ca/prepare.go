package ca

import "github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"

func (c *CA) Prepare(crt *v1alpha1.Certificate) (v1alpha1.CertificateStatus, error) {
	updateStatus := *crt.Status.DeepCopy()

	return updateStatus, nil
}
