/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/test/e2e/framework/addon/chart"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
)

// Vault describes the configuration details for an instance of Vault
// deployed to the test cluster
type Vault struct {
	config        *config.Config
	chart         *chart.Chart
	tillerDetails *tiller.Details

	// Tiller is the tiller instance used to deploy the chart
	Tiller *tiller.Tiller

	// Name is a unique name for this Pebble deployment
	Name string

	// Namespace is the namespace to deploy Pebble into
	Namespace string

	details Details
}

type Details struct {
	// Kubectl is the path to kubectl
	Kubectl string

	// Host is the hostname that can be used to connect to Pebble
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
		return fmt.Errorf("Name field must be set on Pebble addon")
	}
	if v.Namespace == "" {
		// TODO: in non-global instances, we could generate a new namespace just
		// for this addon to be used from.
		return fmt.Errorf("Namespace name must be specified")
	}
	if v.Tiller == nil {
		return fmt.Errorf("Tiller field must be set on Pebble addon")
	}

	var err error
	// Generate CA details before deploying the chart
	v.details.VaultCA, v.details.VaultCAPrivateKey, err = v.generateCA()
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
	v.tillerDetails, err = v.Tiller.Details()
	if err != nil {
		return err
	}
	v.chart = &chart.Chart{
		Tiller:      v.Tiller,
		ReleaseName: "chart-vault-" + v.Name,
		Namespace:   v.Namespace,
		ChartName:   cfg.RepoRoot + "/test/e2e/charts/vault",
		// doesn't matter when installing from disk
		ChartVersion: "0",
		Vars: []chart.StringTuple{
			{
				Key:   "vault.publicKey",
				Value: base64.StdEncoding.EncodeToString(v.details.VaultCert),
			},
			{
				Key:   "vault.privateKey",
				Value: base64.StdEncoding.EncodeToString(v.details.VaultCertPrivateKey),
			},
		},
	}
	err = v.chart.Setup(cfg)
	if err != nil {
		return err
	}
	return nil
}

// Provision will actually deploy this instance of Pebble-ingress to the cluster.
func (v *Vault) Provision() error {
	err := v.chart.Provision()
	if err != nil {
		return err
	}

	// otherwise lookup the newly created pods name
	kubeClient := v.Tiller.Base.Details().KubeClient

	retries := 5
	for {
		pods, err := kubeClient.CoreV1().Pods(v.Namespace).List(metav1.ListOptions{
			LabelSelector: "app=vault",
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
	v.details.Host = fmt.Sprintf("https://vault.%s:8200", v.Namespace)

	return nil
}

// Details returns details that can be used to utilise the instance of Pebble.
func (v *Vault) Details() *Details {
	return &v.details
}

// Deprovision will destroy this instance of Pebble
func (v *Vault) Deprovision() error {
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

func (v *Vault) generateCA() ([]byte, []byte, error) {
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
		DNSNames:     []string{"vault." + v.Namespace},
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
