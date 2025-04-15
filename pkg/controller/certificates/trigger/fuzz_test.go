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

package trigger

import (
	"context"
	"fmt"
	"testing"
	"time"

	gfh "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/internal/controller/certificates/policies"
	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

func mockShouldReissue() policies.Func {
	return func(policies.Input) (string, string, bool) {
		return "ForceTriggered", "Re-issuance forced by unit test case", true
	}
}

// FuzzProcessItem tests the trigger controllers ProcessItem() method.
// It creates up to 10 random certificate requests and up to 10 certificates.
// All of these objects might be invalid and as such the fuzzer
// overapproximates which can result in false positives.
// The fuzzer does not verify how Cert-Manager behaves. It tests for panics
// or unrecoverable issues such as stack overflows, excessive memory usage,
// deadlocks, inifinite loops and other similar issues.
func FuzzProcessItem(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte,
		returnErr bool,
		numberOfCerts,
		numberOfsecrets int) {

		fdp := gfh.NewConsumer(data)
		existingCertificate := &cmapiv1.Certificate{}
		err := fdp.GenerateStruct(existingCertificate)
		if err != nil {
			return
		}

		var certificateName, certificateNamespace string

		// Create up to 10 certificates
		existingCertManagerObjects := make([]runtime.Object, 0)
		for i := range numberOfCerts % 10 {
			cert := &cmapiv1.Certificate{}
			err := fdp.GenerateStruct(cert)
			if err != nil {
				if len(existingCertManagerObjects) == 0 {
					return
				}
				break
			}
			if i == 0 {
				// Save the name and namespace of the first
				// certificate for later.
				certificateName = cert.Name
				certificateNamespace = cert.Namespace
			}
			existingCertManagerObjects = append(existingCertManagerObjects, cert)
		}
		if len(existingCertManagerObjects) == 0 {
			return
		}

		// Create up to 10 secrets
		existingKubeObjects := make([]runtime.Object, 0)
		for range numberOfsecrets % 10 {
			secret := &corev1.Secret{}
			err := fdp.GenerateStruct(secret)
			if err != nil {
				if len(existingKubeObjects) == 0 {
					return
				}
				break
			}
			existingKubeObjects = append(existingKubeObjects, secret)
		}
		if len(existingKubeObjects) == 0 {
			return
		}

		fixedNow := metav1.NewTime(time.Now())
		fixedClock := fakeclock.NewFakeClock(fixedNow.Time)

		// Create the builder
		builder := &testpkg.Builder{
			T:     t,
			Clock: fixedClock,
		}
		builder.CertManagerObjects = append(builder.CertManagerObjects, existingCertificate)
		builder.CertManagerObjects = append(builder.CertManagerObjects, existingCertManagerObjects...)
		builder.KubeObjects = append(builder.KubeObjects, existingKubeObjects...)
		builder.Init()

		w := &controllerWrapper{}
		_, _, err = w.Register(builder.Context)
		if err != nil {
			panic(err)
		}

		w.shouldReissue = func(i policies.Input) (string, string, bool) {
			return mockShouldReissue()(i)
		}

		mockDataForCertificateReturn := policies.Input{}
		mockDataForCertificateReturn.Certificate = existingCertificate

		var mockDataForCertificateReturnErr error
		if returnErr {
			mockDataForCertificateReturnErr = fmt.Errorf("fuzz err")
		} else {
			mockDataForCertificateReturnErr = nil
		}
		w.dataForCertificate = func(context.Context, *cmapiv1.Certificate) (policies.Input, error) {
			return mockDataForCertificateReturn, mockDataForCertificateReturnErr
		}

		builder.Start()
		defer builder.Stop()

		key := types.NamespacedName{
			Name:      certificateName,
			Namespace: certificateNamespace,
		}

		// Call ProcessItem. This is the API that the fuzzer tests.
		_ = w.controller.ProcessItem(context.Background(), key)
	})
}
