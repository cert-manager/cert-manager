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

package issuing

import (
	"context"
	"testing"
	"time"

	gfh "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	testcrypto "github.com/cert-manager/cert-manager/test/unit/crypto"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fuzzBundle testcrypto.CryptoBundle
	baseCert   *cmapiv1.Certificate
)

func init() {
	nextPrivateKeySecretName := "next-private-key"
	baseCert = gen.Certificate("test",
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Name: "ca-issuer", Kind: "Issuer", Group: "foo.io"}),
		gen.SetCertificateGeneration(3),
		gen.SetCertificateSecretName("output"),
		gen.SetCertificateRenewBefore(&metav1.Duration{Duration: time.Hour * 36}),
		gen.SetCertificateDNSNames("example.com"),
		gen.SetCertificateRevision(1),
		gen.SetCertificateNextPrivateKeySecretName(nextPrivateKeySecretName),
	)
	fuzzBundle = testcrypto.MustCreateCryptoBundle(&testing.T{}, baseCert.DeepCopy(), fixedClock)
}

// FuzzProcessItem tests the issuing controllers ProcessItem() method.
// It creates a random certificate, a random secret and a random
// issuing certificate and adds these to the builder. All of these objects
// might be invalid and as such the fuzzer overapproximates which can
// result in false positives.
// The fuzzer does not verify how Cert-Manager behaves. It tests for panics
// or unrecoverable issues such as stack overflows, excessive memory usage,
// deadlocks, inifinite loops and other similar issues.
func FuzzProcessItem(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte,
		randomizeCert,
		randomizeIssuingCert,
		addIssuingCert bool) {

		fdp := gfh.NewConsumer(data)

		// Create the random certificate
		var certificate *cmapiv1.Certificate
		if randomizeCert {
			certificate = &cmapiv1.Certificate{}
			err := fdp.GenerateStruct(certificate)
			if err != nil {
				return
			}
		} else {
			certificate = fuzzBundle.Certificate
			certificate.Name = "test2"
		}
		certManagerObjects := make([]runtime.Object, 0)
		certManagerObjects = append(certManagerObjects, certificate)

		// Create the random secret
		secret := &corev1.Secret{}
		err := fdp.GenerateStruct(secret)
		if err != nil {
			return
		}
		kubeObjects := make([]runtime.Object, 0)
		kubeObjects = append(kubeObjects, secret)

		// Create the random issuing cert
		// The fuzzer itself chooses whether to add this.
		// As such, there may be invocations that do not
		// include an issuing certificate.
		// The fuzzer can randomize this entirely or use
		// a template certificate.
		if addIssuingCert {
			var issuingCert *cmapiv1.Certificate
			if randomizeIssuingCert {
				issuingCert = &cmapiv1.Certificate{}
				err := fdp.GenerateStruct(issuingCert)
				if err != nil {
					return
				}
			} else {
				metaFixedClockStart := metav1.NewTime(fixedClockStart)

				issCert := gen.CertificateFrom(baseCert.DeepCopy(),
					gen.SetCertificateStatusCondition(cmapiv1.CertificateCondition{
						Type:               cmapiv1.CertificateConditionIssuing,
						Status:             cmmeta.ConditionTrue,
						ObservedGeneration: 3,
						LastTransitionTime: &metaFixedClockStart,
					}),
				)
				issuingCert = gen.CertificateFrom(issCert)
			}
			certManagerObjects = append(certManagerObjects, issuingCert)
		}

		// Create the builder
		builder := &testpkg.Builder{}
		builder.CertManagerObjects = certManagerObjects
		builder.KubeObjects = kubeObjects
		fixedClock.SetTime(fixedClockStart)
		builder.Clock = fixedClock
		builder.T = t
		builder.InitWithRESTConfig()
		builder.Start()
		defer builder.Stop()

		w := controllerWrapper{}
		_, _, err = w.Register(builder.Context)
		if err != nil {
			panic(err)
		}
		w.controller.localTemporarySigner = testLocalTemporarySignerFn(fuzzBundle.LocalTemporaryCertificateBytes)

		// Invoke ProcessItem(). This is the method that this fuzzers tests.
		_ = w.controller.ProcessItem(context.Background(), types.NamespacedName{
			Namespace: certificate.Namespace,
			Name:      certificate.Name,
		})
	})
}
