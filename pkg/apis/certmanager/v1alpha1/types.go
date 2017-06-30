package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient=true

type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec CertificateSpec `json:"spec"`
}

type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Certificate `json:"items"`
}

type CertificateSpec struct {
	Domain     string   `json:"domain"`
	Provider   string   `json:"provider"`
	Email      string   `json:"email"`
	SecretName string   `json:"secretName"`
	AltNames   []string `json:"altNames"`
}

type ACMECertData struct {
	DomainName string `json:"domainName"`
	Cert       []byte `json:"cert"`
	PrivateKey []byte `json:"privateKey"`
}

type ACMEUserData struct {
	Email string `json:"email"`
	// Registration *acme.RegistrationResource `json:"registration"`
	Key []byte `json:"key"`
}

type ACMECertDetails struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"certUrl"`
	CertStableURL string `json:"certStableUrl"`
	AccountRef    string `json:"accountRef,omitempty"`
}
