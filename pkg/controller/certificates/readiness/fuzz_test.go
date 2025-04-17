/*
Copyright 2024 The cert-manager Authors.

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

package readiness

import (
	"context"
	"testing"
	"time"

	gfh "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeclock "k8s.io/utils/clock/testing"

	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	privKey []byte
)

func init() {
	privKey = createPEMPrivateKey()
}

// FuzzProcessItem tests the readiness controllers ProcessItem() method.
// It creates a random certificate and a random secret and adds these to
// the builder. All of these objects might be invalid and as such the
// fuzzer overapproximates which can result in false positives.
// The fuzzer does not verify how Cert-Manager behaves. It tests for panics
// or unrecoverable issues such as stack overflows, excessive memory usage,
// deadlocks, inifinite loops and other similar issues.
func FuzzProcessItem(f *testing.F) {
	f.Fuzz(func(t *testing.T, data, randomX509Bytes, pkData []byte, randomizeX509Bytes bool) {
		fdp := gfh.NewConsumer(data)

		// Create the certificate
		cert := &cmapiv1.Certificate{}
		err := fdp.GenerateStruct(cert)
		if err != nil {
			return
		}

		// Create the secret
		secret := &corev1.Secret{}
		err = fdp.GenerateStruct(secret)
		if err != nil {
			return
		}

		now := time.Now().UTC()
		builder := &testpkg.Builder{
			T:     t,
			Clock: fakeclock.NewFakeClock(now),
		}

		// Here the fuzzer can choose to create valid x509 bytes
		// based on the global private key and add these to the
		// secret, or it can use the secret as-is. At this point
		// the fuzzer should already have x509 bytes specified,
		// although they can be invalid if considering a real-
		// world usecase. For example, they can contain non-
		// alphanumeric characters.
		var x509Bytes []byte
		mods := make([]gen.SecretModifier, 0)
		if !randomizeX509Bytes {
			newX509Bytes, err := createSignedCertificate(privKey, cert)
			if err != nil {
				x509Bytes = randomX509Bytes
			} else {
				x509Bytes = newX509Bytes
			}
			mods = append(mods,
				gen.SetSecretData(map[string][]byte{
					"tls.crt": x509Bytes,
				}))
			builder.KubeObjects = append(builder.KubeObjects,
				gen.SecretFrom(secret, mods...))
		} else {
			builder.KubeObjects = append(builder.KubeObjects, secret)
		}

		builder.CertManagerObjects = append(builder.CertManagerObjects, cert)
		builder.Init()
		w := &controllerWrapper{}
		_, _, err = w.Register(builder.Context)
		if err != nil {
			panic(err)
		}
		builder.Start()
		defer builder.Stop()

		key := types.NamespacedName{
			Name:      cert.Name,
			Namespace: cert.Namespace,
		}
		// Call ProcessItem. This is the API that the fuzzer tests.
		_ = w.controller.ProcessItem(context.Background(), key)
	})
}

// MustCreatePEMPrivateKey returns a PEM encoded 2048 bit RSA private key
func createPEMPrivateKey() []byte {
	pk, err := pki.GenerateRSAPrivateKey(2048)
	if err != nil {
		panic(err)
	}
	pkData, err := pki.EncodePrivateKey(pk, cmapiv1.PKCS8)
	if err != nil {
		panic(err)
	}
	return pkData
}

func createSignedCertificate(pkData []byte, spec *cmapiv1.Certificate) ([]byte, error) {
	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		return []byte(""), err
	}
	template, err := pki.CertificateTemplateFromCertificate(spec)
	if err != nil {
		return []byte(""), err
	}
	clock := &fakeclock.FakeClock{}
	template.NotBefore = clock.Now()
	template.NotAfter = clock.Now().Add(time.Hour * 3)

	certData, _, err := pki.SignCertificate(template, template, pk.Public(), pk)
	if err != nil {
		return []byte(""), err
	}

	return certData, nil
}
