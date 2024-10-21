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

package tls

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	logtesting "github.com/go-logr/logr/testing"
	"golang.org/x/sync/errgroup"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

func TestFileSource_ReadsFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "test-filesource-readsfile-")
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
		log:            logtesting.NewTestLogger(t),
	}
	ctx, cancel := context.WithCancel(logr.NewContext(context.Background(), logtesting.NewTestLogger(t)))
	errGroup := new(errgroup.Group)
	errGroup.Go(func() error {
		return source.Start(ctx)
	})

	time.Sleep(interval * 2)
	cert, err := source.GetCertificate(nil)
	if err != nil {
		cancel()
		t.Fatalf("got an unexpected error: %v", err)
	}
	x509Crt, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		cancel()
		t.Fatalf("failed to decode x509 certificate: %v", err)
	}
	if x509Crt.Subject.SerialNumber != serial {
		cancel()
		t.Errorf("certificate had unexpected serial number. exp=%s, got=%s", serial, x509Crt.Subject.SerialNumber)
	}
	cancel()
	if err := errGroup.Wait(); err != nil {
		t.Errorf("FileCertificateSource failed %v", err)
	}
}

func TestFileSource_UpdatesFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "test-filesource-updatesfile-")
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
	}
	ctx, cancel := context.WithCancel(logr.NewContext(context.Background(), logtesting.NewTestLogger(t)))
	errGroup := new(errgroup.Group)
	errGroup.Go(func() error {
		return source.Start(ctx)
	})

	time.Sleep(interval * 2)
	cert, err := source.GetCertificate(nil)
	if err != nil {
		cancel()
		t.Fatalf("got an unexpected error: %v", err)
	}
	x509Crt, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		cancel()
		t.Fatalf("failed to decode x509 certificate: %v", err)
	}
	if x509Crt.Subject.SerialNumber != serial {
		cancel()
		t.Errorf("certificate had unexpected serial number. exp=%s, got=%s", serial, x509Crt.Subject.SerialNumber)
	}

	// Update the certificate data in-place
	serial = "serial2"
	pkBytes, certBytes = generatePrivateKeyAndCertificate(t, serial)
	writeTempFile(t, dir, "pk", pkBytes)
	writeTempFile(t, dir, "cert", certBytes)

	time.Sleep(interval * 2)
	cert, err = source.GetCertificate(nil)
	if err != nil {
		cancel()
		t.Fatalf("got an unexpected error: %v", err)
	}
	x509Crt, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		cancel()
		t.Fatalf("failed to decode x509 certificate: %v", err)
	}
	if x509Crt.Subject.SerialNumber != serial {
		cancel()
		t.Errorf("certificate had unexpected serial number. exp=%s, got=%s", serial, x509Crt.Subject.SerialNumber)
	}

	cancel()
	if err := errGroup.Wait(); err != nil {
		t.Errorf("FileCertificateSource failed: %v", err)
	}
}

func generatePrivateKeyAndCertificate(t *testing.T, serial string) ([]byte, []byte) {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pkBytes, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := cmrand.SerialNumber()
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
