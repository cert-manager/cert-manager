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

package requestmanager

import (
	"context"
	"testing"
	"time"

	gfh "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	globalBundle *cryptoBundle
)

func init() {
	var err error
	globalBundle, err = createCryptoBundle(&cmapiv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "testns",
			Name:      "test",
			UID:       "test",
		},
		Spec: cmapiv1.CertificateSpec{CommonName: "test-bundle-1"}},
	)
	if err != nil {
		panic(err)
	}
}

// FuzzProcessItem tests the requestmanager controllers ProcessItem() method.
// It creates up to 10 random certificate requests, 1 certificate, a secret
// and adds these to the builder. All of these objects might be invalid and
// as such the fuzzer overapproximates which can result in false positives.
// The fuzzer does not verify how Cert-Manager behaves. It tests for panics
// or unrecoverable issues such as stack overflows, excessive memory usage,
// deadlocks, inifinite loops and other similar issues.
func FuzzProcessItem(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte,
		numberOfRequests int,
		useStableCertificateRequestName,
		randomizeCertificate,
		randomizeSecret bool) {
		fdp := gfh.NewConsumer(data)

		// Create up to 10 random certificate requests
		requests := make([]runtime.Object, 0)
		for range numberOfRequests % 10 {
			request := &cmapiv1.CertificateRequest{}
			err := fdp.GenerateStruct(request)
			if err != nil {
				if len(requests) == 0 {
					return
				}
				break
			}
			requests = append(requests, request)
		}

		// Create a certificate and a secret
		// The certificate can be entirely random, or the fuzzer
		// can generate one from the global bundle.
		var certificate *cmapiv1.Certificate
		var secret *corev1.Secret
		if randomizeCertificate {
			certificate = &cmapiv1.Certificate{}
			err := fdp.GenerateStruct(certificate)
			if err != nil {
				return
			}
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: certificate.Namespace, Name: "secret"},
				Data:       map[string][]byte{corev1.TLSPrivateKeyKey: globalBundle.privateKeyBytes},
			}
		} else {
			certificate = gen.CertificateFrom(globalBundle.certificate,
				gen.SetCertificateNextPrivateKeySecretName("secret"),
				gen.SetCertificateStatusCondition(cmapiv1.CertificateCondition{Type: cmapiv1.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}))
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: globalBundle.certificate.Namespace, Name: "secret"},
				Data:       map[string][]byte{corev1.TLSPrivateKeyKey: globalBundle.privateKeyBytes},
			}
		}

		// At this point, the fuzzer has created a valid secret.
		// To allow it to test for invalid edge cases too, we
		// give it the option to create a new, possibly invalid
		// secret which is entirely random. If the fuzzer fails
		// to randomize the secret here, it uses the valid secret
		// instead.
		if randomizeSecret {
			randomSecret := &corev1.Secret{}
			err := fdp.GenerateStruct(randomSecret)
			if err == nil {
				secret = randomSecret
			}
		}
		secrets := []runtime.Object{secret}
		fixedNow := metav1.NewTime(time.Now())
		fixedClock := fakeclock.NewFakeClock(fixedNow.Time)

		// Create the builder
		builder := &testpkg.Builder{
			T:               t,
			StringGenerator: func(i int) string { return "notrandom" },
			Clock:           fixedClock,
		}

		// Add the created objects to the builder
		builder.CertManagerObjects = append(builder.CertManagerObjects, certificate)
		builder.KubeObjects = append(builder.KubeObjects, secrets...)
		builder.CertManagerObjects = append(builder.CertManagerObjects, requests...)

		builder.Init()
		w := &controllerWrapper{}
		_, _, err := w.Register(builder.Context)
		if err != nil {
			panic(err)
		}
		key := types.NamespacedName{
			Name:      certificate.Name,
			Namespace: certificate.Namespace,
		}

		// Enable feature settings that will otherwise
		// block the fuzzer.
		featuregatetesting.SetFeatureGateDuringTest(t,
			utilfeature.DefaultFeatureGate,
			feature.StableCertificateRequestName,
			useStableCertificateRequestName)

		builder.Start()
		defer builder.Stop()

		// Call ProcessItem. This is the API that the fuzzer tests.
		_ = w.controller.ProcessItem(context.Background(), key)
	})
}
