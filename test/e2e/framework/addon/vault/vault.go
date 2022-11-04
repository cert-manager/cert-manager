/*
Copyright 2020 The cert-manager Authors.

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

// package vault contains an addon that installs Vault
package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/test/e2e/framework/addon/base"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon/chart"
	"github.com/cert-manager/cert-manager/test/e2e/framework/config"
)

const (
	vaultHelmChartRepo    = "https://helm.releases.hashicorp.com"
	vaultHelmChartVersion = "0.22.0"
	vaultImageRepository  = "index.docker.io/library/vault"
	vaultImageTag         = "1.2.3@sha256:b1c86c9e173f15bb4a926e4144a63f7779531c30554ac7aee9b2a408b22b2c01"
)

// Vault describes the configuration details for an instance of Vault
// deployed to the test cluster
type Vault struct {
	chart     *chart.Chart
	tlsSecret corev1.Secret

	Base *base.Base

	// Name is a unique name for this Vault deployment
	Name string

	// Namespace is the namespace to deploy Vault into
	Namespace string

	details Details
}

type Details struct {
	// Kubectl is the path to kubectl
	Kubectl string

	// Host is the hostname that can be used to connect to Vault
	Host string

	// PodName is the name of the Vault pod
	PodName string

	// Namespace is the namespace vault has been deployed into
	Namespace string

	// VaultCA is the CA used to sign the vault serving certificate
	VaultCA           []byte
	VaultCAPrivateKey []byte

	// VaultCert is the vault serving certificate
	VaultCert           []byte
	VaultCertPrivateKey []byte
}

func (v *Vault) Setup(cfg *config.Config) error {
	if v.Name == "" {
		return fmt.Errorf("Name field must be set on Vault addon")
	}
	if v.Namespace == "" {
		// TODO: in non-global instances, we could generate a new namespace just
		// for this addon to be used from.
		return fmt.Errorf("Namespace name must be specified")
	}
	if v.Base == nil {
		return fmt.Errorf("Base field must be set on Vault addon")
	}

	var err error
	// Generate CA details before deploying the chart
	v.details.VaultCA, v.details.VaultCAPrivateKey, err = v.GenerateCA()
	if err != nil {
		return err
	}
	v.details.VaultCert, v.details.VaultCertPrivateKey, err = v.generateCert()
	if err != nil {
		return err
	}
	if cfg.Kubectl == "" {
		return fmt.Errorf("path to kubectl must be set")
	}
	v.details.Kubectl = cfg.Kubectl
	v.chart = &chart.Chart{
		Base:         v.Base,
		ReleaseName:  "chart-vault-" + v.Name,
		Namespace:    v.Namespace,
		ChartName:    "hashicorp/vault",
		ChartVersion: vaultHelmChartVersion,
		Repo: chart.Repo{
			Name: "hashicorp",
			Url:  vaultHelmChartRepo,
		},
		Vars: []chart.StringTuple{
			{
				Key:   "injector.enabled",
				Value: "false",
			},
			{
				Key:   "server.authDelegator.enabled",
				Value: "false",
			},
			{
				Key:   "server.dataStorage.enabled",
				Value: "false",
			},
			{
				Key:   "server.standalone.enabled",
				Value: "true",
			},
			// configure dev mode
			// we cannot use the 'server.dev.enabled' Helm value here, because as soon
			// as you enable 'server.dev' you cannot specify a config file anymore
			{
				Key:   "server.extraArgs",
				Value: "-dev -dev-listen-address=[::]:8202",
			},
			// configure root token
			{
				Key:   "server.extraEnvironmentVars.VAULT_DEV_ROOT_TOKEN_ID",
				Value: "vault-root-token",
			},
			// configure tls certificate
			{
				Key:   "global.tlsDisable",
				Value: "false",
			},
			{
				Key: "server.standalone.config",
				Value: `
				listener "tcp" {
					address = "[::]:8200"
					cluster_address = "[::]:8201"
					tls_disable = false
					tls_cert_file = "/vault/tls/server.crt"
					tls_key_file = "/vault/tls/server.key"
				}`,
			},
			{
				Key:   "server.volumes[0].name",
				Value: "vault-tls",
			},
			{
				Key:   "server.volumes[0].secret.secretName",
				Value: "vault-tls",
			},
			{
				Key:   "server.volumeMounts[0].name",
				Value: "vault-tls",
			},
			{
				Key:   "server.volumeMounts[0].mountPath",
				Value: "/vault/tls",
			},
			// configure image and repo
			{
				Key:   "server.image.repository",
				Value: vaultImageRepository,
			},
			{
				Key:   "server.image.tag",
				Value: vaultImageTag,
			},
			// configure resource requests and limits
			{
				Key:   "server.resources.requests.cpu",
				Value: "50m",
			},
			{
				Key:   "server.resources.requests.memory",
				Value: "64Mi",
			},
			{
				Key:   "server.resources.limits.cpu",
				Value: "200m",
			},
			{
				Key:   "server.resources.limits.memory",
				Value: "256Mi",
			},
		},
	}
	err = v.chart.Setup(cfg)
	if err != nil {
		return err
	}

	v.tlsSecret = corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-tls",
			Namespace: v.Namespace,
		},
		StringData: map[string]string{
			"server.crt": string(v.details.VaultCert),
			"server.key": string(v.details.VaultCertPrivateKey),
		},
	}

	return nil
}

// Provision will actually deploy this instance of Vault to the cluster.
func (v *Vault) Provision() error {
	kubeClient := v.Base.Details().KubeClient

	_, err := kubeClient.CoreV1().Secrets(v.Namespace).Create(context.TODO(), &v.tlsSecret, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	err = v.chart.Provision()
	if err != nil {
		return err
	}

	// lookup the newly created pods name
	retries := 5
	for {
		pods, err := kubeClient.CoreV1().Pods(v.Namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=vault",
		})
		if err != nil {
			return err
		}
		if len(pods.Items) == 0 {
			if retries == 0 {
				return fmt.Errorf("failed to create vault pod within 10s")
			}
			retries--
			time.Sleep(time.Second * 2)
			continue
		}
		vaultPod := pods.Items[0]
		// If the vault pod exists but is just waiting to be created, we allow
		// it a bit longer.
		if len(vaultPod.Status.ContainerStatuses) == 0 || !vaultPod.Status.ContainerStatuses[0].Ready {
			retries--
			time.Sleep(time.Second * 5)
			continue
		}
		v.details.PodName = vaultPod.Name
		break
	}

	v.details.Namespace = v.Namespace
	v.details.Host = fmt.Sprintf("https://%s:8200", "chart-vault-"+v.Name+"."+v.Namespace)

	return nil
}

// Details returns details that can be used to utilise the instance of Vault.
func (v *Vault) Details() *Details {
	return &v.details
}

// Deprovision will destroy this instance of Vault
func (v *Vault) Deprovision() error {
	kubeClient := v.Base.Details().KubeClient

	err := kubeClient.CoreV1().Secrets(v.Namespace).Delete(context.TODO(), v.tlsSecret.Name, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	return v.chart.Deprovision()
}

func (v *Vault) SupportsGlobal() bool {
	// We don't support global instances of vault currently as we need to generate
	// PKI details at deploy time and make them available to tests.
	return false
}

func (v *Vault) Logs() (map[string]string, error) {
	return v.chart.Logs()
}

func (v *Vault) GenerateCA() ([]byte, []byte, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization: []string{"cert-manager test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := &privateKey.PublicKey
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create ca failed: %v", err)
	}

	return encodePublicKey(caBytes), encodePrivateKey(privateKey), nil
}

func (v *Vault) generateCert() ([]byte, []byte, error) {
	catls, err := tls.X509KeyPair(v.details.VaultCA, v.details.VaultCAPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing ca key pair failed: %s", err.Error())
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parsing ca failed: %s", err.Error())
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   "vault." + v.Namespace,
			Organization: []string{"cert-manager vault server"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"chart-vault-" + v.Name + "." + v.Namespace},
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("private key generation failed: %s", err.Error())
	}

	publicKey := &privateKey.PublicKey

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, publicKey, catls.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return encodePublicKey(certBytes), encodePrivateKey(privateKey), nil
}

func encodePublicKey(pub []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pub})
}

func encodePrivateKey(priv *rsa.PrivateKey) []byte {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}

	return pem.EncodeToMemory(block)
}
