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

package keymanager

import (
	"context"
	"testing"

	gfh "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	cmapiv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

// FuzzProcessItem tests the keymanager controllers ProcessItem()
// method. It creates a fully-randomized certificate, secret and
// multiple random requests and adds all of these to the builder.
// These objects may be invalid compared to a real-world use case
// and as such the fuzzer overapproximates. Depending on the
// number of false positives, this case be adjusted over time.
//
// The fuzzer does not verify how Cert-Manager behaves. It tests for panics
// or unrecoverable issues such as stack overflows, excessive memory usage,
// deadlocks, inifinite loops and other similar issues.
func FuzzProcessItem(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, numberOfRequests int) {
		fdp := gfh.NewConsumer(data)

		// Create a fully random certificate
		// This may be invalid.
		certificate := &cmapiv1.Certificate{}
		err := fdp.GenerateStruct(certificate)
		if err != nil {
			return
		}
		// Create a fully random secret
		// This may be invalid.
		secret := &corev1.Secret{}
		err = fdp.GenerateStruct(secret)
		if err != nil {
			return
		}

		// Create fully random requests. these may be invalid.
		requests := make([]*cmapiv1.CertificateRequest, 0)
		for range numberOfRequests % 10 {
			request := &cmapiv1.CertificateRequest{}
			err = fdp.GenerateStruct(request)
			if err != nil {
				if len(requests) == 0 {
					return
				}
			}
			requests = append(requests, request)
		}

		// Create the builder
		builder := &testpkg.Builder{
			T:               t,
			StringGenerator: func(i int) string { return "notrandom" },
		}
		builder.CertManagerObjects = append(builder.CertManagerObjects, certificate)
		builder.KubeObjects = append(builder.KubeObjects, secret)
		for _, req := range requests {
			builder.CertManagerObjects = append(builder.CertManagerObjects, req)
		}
		builder.Init()

		w := &controllerWrapper{}
		_, _, err = w.Register(builder.Context)
		if err != nil {
			t.Fatal(err)
		}
		builder.Start()
		defer builder.Stop()

		key := types.NamespacedName{
			Name:      certificate.Name,
			Namespace: certificate.Namespace,
		}
		// Call ProcessItem. This is the API that the fuzzer tests.
		_ = w.controller.ProcessItem(context.Background(), key)
	})
}
