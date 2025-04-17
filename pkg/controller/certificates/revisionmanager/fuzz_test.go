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

package revisionmanager

import (
	"context"
	"testing"

	gfh "github.com/AdaLogics/go-fuzz-headers"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
)

// FuzzProcessItem tests the revisionmanager controllers ProcessItem() method.
// It creates up to 10 random certificate requests and up to 10 certificates.
// All of these objects might be invalid and as such the fuzzer
// overapproximates which can result in false positives.
// The fuzzer does not verify how Cert-Manager behaves. It tests for panics
// or unrecoverable issues such as stack overflows, excessive memory usage,
// deadlocks, inifinite loops and other similar issues.
func FuzzProcessItem(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		data []byte,
		numberOfCerts,
		numberOfRequests int,
	) {
		var certificateName, certificateNamespace string
		fdp := gfh.NewConsumer(data)

		// Create up to 10 random certificate requests
		requests := make([]runtime.Object, 0)
		for range numberOfRequests % 10 {
			request := &v1.CertificateRequest{}
			err := fdp.GenerateStruct(request)
			if err != nil {
				if len(requests) == 0 {
					return
				}
				break
			}
			requests = append(requests, request)
		}
		if len(requests) == 0 {
			return
		}

		// Create up to 10 random certificates
		existingCertManagerObjects := make([]runtime.Object, 0)
		for i := range numberOfCerts % 10 {
			cert := &v1.Certificate{}
			err := fdp.GenerateStruct(cert)
			if err != nil {
				// If the fuzzer fails to create a certificate
				// here, we return if it has not created
				// any certificates. If it has created one or
				// more certificates, the fuzzer proceeds with
				// that.
				if len(existingCertManagerObjects) == 0 {
					return
				}
				break
			}
			if i == 0 {
				certificateName = cert.Name
				certificateNamespace = cert.Namespace
			}
			existingCertManagerObjects = append(existingCertManagerObjects, cert)
		}

		// Create the builder
		builder := &testpkg.Builder{
			T:               t,
			StringGenerator: func(i int) string { return "notrandom" },
		}
		// Add created objects to builder
		builder.CertManagerObjects = append(builder.CertManagerObjects, existingCertManagerObjects...)
		builder.CertManagerObjects = append(builder.CertManagerObjects, requests...)

		builder.Init()

		// Register informers used by the controller using the registration wrapper
		w := &controllerWrapper{}
		_, _, err := w.Register(builder.Context)
		if err != nil {
			t.Fatal(err)
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
