/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package tls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	logtesting "github.com/jetstack/cert-manager/pkg/logs/testing"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

func TestFileSource_ReadsFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "test-temp-dir-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}()

	serial := "serial1"
	pkBytes, certBytes := generatePrivateKeyAndCertificate(t, serial)
	pkFile := writeTempFile(t, dir, "pk", pkBytes)
	certFile := writeTempFile(t, dir, "cert", certBytes)

	interval := time.Millisecond * 500
	source := FileCertificateSource{
		CertPath:       certFile,
		KeyPath:        pkFile,
		UpdateInterval: interval,
		Log:            logtesting.TestLogger{T: t},
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go source.Run(stopCh)

	time.Sleep(interval * 2)
	cert, err := source.GetCertificate(nil)
	if err != nil {
		t.Fatalf("got an unexpected error: %v", err)
	}
	x509Crt, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to decode x509 certificate: %v", err)
	}
	if x509Crt.Subject.SerialNumber != serial {
		t.Errorf("certificate had unexpected serial number. exp=%s, got=%s", serial, x509Crt.Subject.SerialNumber)
	}
}

func TestFileSource_UpdatesFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "test-temp-dir-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}()

	serial := "serial1"
	pkBytes, certBytes := generatePrivateKeyAndCertificate(t, serial)
	pkFile := writeTempFile(t, dir, "pk", pkBytes)
	certFile := writeTempFile(t, dir, "cert", certBytes)

	interval := time.Millisecond * 500
	source := FileCertificateSource{
		CertPath:       certFile,
		KeyPath:        pkFile,
		UpdateInterval: interval,
		Log:            logtesting.TestLogger{T: t},
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	go source.Run(stopCh)

	time.Sleep(interval * 2)
	cert, err := source.GetCertificate(nil)
	if err != nil {
		t.Fatalf("got an unexpected error: %v", err)
	}
	x509Crt, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to decode x509 certificate: %v", err)
	}
	if x509Crt.Subject.SerialNumber != serial {
		t.Errorf("certificate had unexpected serial number. exp=%s, got=%s", serial, x509Crt.Subject.SerialNumber)
	}

	// Update the certificate data in-place
	serial = "serial2"
	pkBytes, certBytes = generatePrivateKeyAndCertificate(t, serial)
	pkFile = writeTempFile(t, dir, "pk", pkBytes)
	certFile = writeTempFile(t, dir, "cert", certBytes)

	time.Sleep(interval * 2)
	cert, err = source.GetCertificate(nil)
	if err != nil {
		t.Fatalf("got an unexpected error: %v", err)
	}
	x509Crt, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to decode x509 certificate: %v", err)
	}
	if x509Crt.Subject.SerialNumber != serial {
		t.Errorf("certificate had unexpected serial number. exp=%s, got=%s", serial, x509Crt.Subject.SerialNumber)
	}
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func generatePrivateKeyAndCertificate(t *testing.T, serial string) ([]byte, []byte) {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pkBytes, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.RSA,
		Subject: pkix.Name{
			SerialNumber: serial,
			CommonName:   "example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute * 10),
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, cert, err = pki.SignCertificate(cert, cert, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := pki.EncodeX509(cert)
	if err != nil {
		t.Fatal(err)
	}

	return pkBytes, certBytes
}

func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}

	return f.Name()
}
