package cfssl

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os/exec"
	"time"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	chartName = "./contrib/charts/cfssl"
)

func NewAuthKeySecret(name, authKey string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		StringData: map[string]string{
			"auth-key": authKey,
		},
	}
}

func NewCFSSLServerSecret(name string, keyAlgo v1alpha1.KeyAlgorithm, keySize int) (*v1.Secret, error) {
	privKey, pubKey, err := generateKeyPair(keyAlgo, keySize)
	if err != nil {
		return nil, err
	}

	certBytes, err := generateCACertificate(privKey, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA cert: %s", err)
	}

	keyBytes, err := pki.EncodePrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %s", err)
	}

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Data: map[string][]byte{
			"ca.pem":     certBytes,
			"ca-key.pem": keyBytes,
		},
	}, nil
}

func InstallHelmChart(releaseName, namespace, values string) error {
	args := []string{"install", chartName, "--namespace", namespace, "--name", releaseName, "--values", values, "--wait"}
	cmd := exec.Command("helm", args...)
	return runCommand(cmd)
}

func DeleteHelmChart(releaseName string) error {
	args := []string{"delete", releaseName, "--purge"}
	cmd := exec.Command("helm", args...)
	return runCommand(cmd)
}

func generateKeyPair(keyAlgo v1alpha1.KeyAlgorithm, keySize int) (crypto.PrivateKey, crypto.PublicKey, error) {
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey

	switch keyAlgo {
	case v1alpha1.RSAKeyAlgorithm:
		key, err := pki.GenerateRSAPrivateKey(keySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate private key: %s", err)
		}
		pubKey = key.Public()
		privKey = key

	case v1alpha1.ECDSAKeyAlgorithm:
		key, err := pki.GenerateECPrivateKey(keySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate private key: %s", err)
		}
		pubKey = key.Public()
		privKey = key

	default:
		return nil, nil, fmt.Errorf("unsupported key algorithm specified: %s", keyAlgo)
	}

	return privKey, pubKey, nil
}

func generateCACertificate(privKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Organization: []string{"cfssl-test-ca"},
			CommonName:   "cfssl-test-ca",
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames:       []string{"cfssl-test-ca"},
		IsCA:           true,
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 certificate: %s", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return pemBytes, nil
}

func runCommand(cmd *exec.Cmd) error {
	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error running command: %s\n%s", err, stderr.Bytes())
	}

	fmt.Printf("%s\n", stdout.Bytes())
	return nil
}
