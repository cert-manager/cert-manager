package certmanager

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient=true

type Certificate struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec CertificateSpec
}

type CertificateList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Certificate
}

type CertificateSpec struct {
	Domain     string
	Provider   string
	Email      string
	SecretName string
	AltNames   []string
}

type ACMECertData struct {
	DomainName string
	Cert       []byte
	PrivateKey []byte
}

type ACMEUserData struct {
	Email string
	// Registration *acme.RegistrationResource
	Key []byte
}

type ACMECertDetails struct {
	Domain        string
	CertURL       string
	CertStableURL string
	AccountRef    string
}
