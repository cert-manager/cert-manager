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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/base"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/chart"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/internal"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/config"
)

const (
	vaultHelmChartRepo    = "https://helm.releases.hashicorp.com"
	vaultHelmChartVersion = "0.25.0"
)

// Vault describes the configuration details for an instance of Vault
// deployed to the test cluster
type Vault struct {
	chart *chart.Chart

	Base *base.Base

	// Name is a unique name for this Vault deployment
	Name string

	// Namespace is the namespace to deploy Vault into
	Namespace string

	// Proxy is the proxy that can be used to connect to Vault
	proxy *proxy

	// vaultCert and vaultCertPrivateKey are the certificate and private key
	// used to sign the Vault serving certificate
	vaultCert, vaultCertPrivateKey []byte

	details Details
}

var _ internal.Addon = &Vault{}

type Details struct {
	// URL is the url that can be used to connect to Vault inside the cluster
	URL string

	// ProxyURL is the url that can be used to connect to Vault outside of the cluster
	ProxyURL string

	// VaultCA is the CA used to sign the vault serving certificate
	VaultCA []byte
}

func convertInterfaceToDetails(unmarshalled interface{}) (Details, error) {
	jsonEncoded, err := json.Marshal(unmarshalled)
	if err != nil {
		return Details{}, err
	}

	var details Details
	err = json.Unmarshal(jsonEncoded, &details)
	if err != nil {
		return Details{}, err
	}

	return details, nil
}

func (v *Vault) Setup(cfg *config.Config, leaderData ...internal.AddonTransferableData) (internal.AddonTransferableData, error) {
	if v.Name == "" {
		return nil, fmt.Errorf("'Name' field must be set on Vault addon")
	}
	if v.Namespace == "" {
		// TODO: in non-global instances, we could generate a new namespace just
		// for this addon to be used from.
		return nil, fmt.Errorf("'Namespace' name must be specified")
	}
	if v.Base == nil {
		return nil, fmt.Errorf("'Base' field must be set on Vault addon")
	}

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
				Value: "-dev-tls -dev-listen-address=[::]:8202",
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
					tls_disable = false
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
			// configure resource requests
			{
				Key:   "server.resources.requests.cpu",
				Value: "50m",
			},
			{
				Key:   "server.resources.requests.memory",
				Value: "64Mi",
			},
		},
	}

	// When the tests have been launched by make, the cluster will be a kind
	// cluster into which we will have loaded some locally cached Vault images.
	// But we also want people to be able to compile the E2E test binary and run
	// the tests on their chosen cluster, in which case we do not override the
	// Vault image and the default chart image will be downloaded and run
	// instead.
	// E2E_VAULT_IMAGE is exported by `make/e2e-setup.mk`.
	if vaultImage := os.Getenv("E2E_VAULT_IMAGE"); vaultImage != "" {
		parts := strings.Split(vaultImage, ":")
		vaultImageRepository := parts[0]
		vaultImageTag := parts[1]
		v.chart.Vars = append(
			v.chart.Vars,
			[]chart.StringTuple{
				// configure image and repo
				{
					Key:   "server.image.repository",
					Value: vaultImageRepository,
				},
				{
					Key:   "server.image.tag",
					Value: vaultImageTag,
				},
				{
					Key:   "server.image.pullPolicy",
					Value: "Never",
				},
			}...,
		)
	}

	// Set E2E_OPENSHIFT=true if you're running the E2E tests against an OpenShift
	// cluster.
	// OpenShift requires some different settings. See
	// https://developer.hashicorp.com/vault/tutorials/kubernetes/kubernetes-openshift
	if os.Getenv("E2E_OPENSHIFT") == "true" {
		v.chart.Vars = append(
			v.chart.Vars,
			[]chart.StringTuple{
				{
					Key:   "global.openshift",
					Value: "true",
				},
			}...,
		)
	}

	_, err := v.chart.Setup(cfg)
	if err != nil {
		return nil, err
	}

	if len(leaderData) == 1 {
		details, err := convertInterfaceToDetails(leaderData[0])
		if err != nil {
			return nil, fmt.Errorf("leader data is not of type Details: %w", err)
		}
		v.details = details
	} else {
		dnsName := fmt.Sprintf("%s.%s.svc.cluster.local", v.chart.ReleaseName, v.Namespace)

		// Generate CA details before deploying the chart
		vaultCA, vaultCAPrivateKey, err := GenerateCA()
		if err != nil {
			return nil, err
		}
		v.details.VaultCA = vaultCA

		v.vaultCert, v.vaultCertPrivateKey, err = generateVaultServingCert(vaultCA, vaultCAPrivateKey, dnsName)
		if err != nil {
			return nil, err
		}

		if cfg.Kubectl == "" {
			return nil, fmt.Errorf("path to kubectl must be specified")
		}
		v.proxy = newProxy(
			v.Base.Details().KubeClient,
			v.Base.Details().KubeConfig,
			v.Namespace,
			fmt.Sprintf("%s-0", v.chart.ReleaseName),
			vaultCA,
		)

		v.details.URL = fmt.Sprintf("https://%s:8200", dnsName)
		v.details.ProxyURL = fmt.Sprintf("https://127.0.0.1:%d", v.proxy.listenPort)
	}

	return v.details, nil
}

// Provision will actually deploy this instance of Vault to the cluster.
func (v *Vault) Provision() error {
	kubeClient := v.Base.Details().KubeClient

	// If the namespace doesn't exist, create it
	_, err := kubeClient.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: v.Namespace,
		},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	// Create the TLS secret
	tlsSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vault-tls",
			Namespace: v.Namespace,
		},
		StringData: map[string]string{
			"server.crt": string(v.vaultCert),
			"server.key": string(v.vaultCertPrivateKey),
		},
	}
	_, err = kubeClient.CoreV1().Secrets(v.Namespace).Create(context.TODO(), tlsSecret, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	// Deploy the vault chart
	err = v.chart.Provision()
	if err != nil {
		return err
	}

	// Wait for the vault pod to be ready
	{
		allContainersReady := func(pod *corev1.Pod) bool {
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if !containerStatus.Ready {
					return false
				}
			}
			return true
		}

		var lastError error
		err = wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
			pod, err := kubeClient.CoreV1().Pods(v.proxy.podNamespace).Get(context.TODO(), v.proxy.podName, metav1.GetOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				return false, err
			}

			if err != nil && apierrors.IsNotFound(err) {
				lastError = fmt.Errorf("pod not found")
				return false, nil
			}

			if pod.Status.Phase != corev1.PodRunning {
				lastError = fmt.Errorf("pod is not running, current phase: %s", pod.Status.Phase)
				return false, nil
			}

			if !allContainersReady(pod) {
				lastError = fmt.Errorf("pod has containers that are not ready: %v", pod.Status.ContainerStatuses)
				return false, nil
			}

			return true, nil
		})
		if err != nil {
			logs, err := kubeClient.
				CoreV1().
				Pods(v.proxy.podNamespace).
				GetLogs(v.proxy.podName, &corev1.PodLogOptions{
					TailLines: ptr.To(int64(100)),
				}).
				DoRaw(context.TODO())

			if err != nil {
				return fmt.Errorf("error waiting for vault pod to be ready: %w; failed to retrieve logs: %w", lastError, err)
			}

			return fmt.Errorf("error waiting for vault pod to be ready: %w; logs: %s", lastError, logs)
		}
	}

	if err := v.proxy.start(); err != nil {
		return err
	}

	return nil
}

// Details returns details that can be used to utilise the instance of Vault.
func (v *Vault) Details() *Details {
	return &v.details
}

// Deprovision will destroy this instance of Vault
func (v *Vault) Deprovision() error {
	if err := v.proxy.stop(); err != nil {
		return err
	}

	kubeClient := v.Base.Details().KubeClient
	err := kubeClient.CoreV1().Secrets(v.Namespace).Delete(context.TODO(), "vault-tls", metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	return v.chart.Deprovision()
}

func (v *Vault) SupportsGlobal() bool {
	return v.chart.SupportsGlobal()
}

func (v *Vault) Logs() (map[string]string, error) {
	return v.chart.Logs()
}

func generateVaultServingCert(vaultCA []byte, vaultCAPrivateKey []byte, dnsName string) ([]byte, []byte, error) {
	catls, _ := tls.X509KeyPair(vaultCA, vaultCAPrivateKey)
	ca, _ := x509.ParseCertificate(catls.Certificate[0])

	cert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   dnsName,
			Organization: []string{"cert-manager vault server"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{dnsName},
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, ca, &privateKey.PublicKey, catls.PrivateKey)

	return encodePublicKey(certBytes), encodePrivateKey(privateKey), nil
}

func GenerateCA() ([]byte, []byte, error) {
	ca := &x509.Certificate{
		Version:      3,
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
	caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)

	return encodePublicKey(caBytes), encodePrivateKey(privateKey), nil
}

func encodePublicKey(pub []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pub})
}

func encodePrivateKey(priv *rsa.PrivateKey) []byte {
	pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}
	return pem.EncodeToMemory(block)
}
