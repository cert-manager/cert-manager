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

package approval

import (
	"context"
	"testing"

	gfh "github.com/AdaLogics/go-fuzz-headers"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/cert-manager/cert-manager/internal/apis/certmanager"
	discoveryfake "github.com/cert-manager/cert-manager/test/unit/discovery"
)

// FuzzValidate tests the approval validation with
// random CRs. It can be run with `go test -fuzz=FuzzValidate`.
// It tests for panics, OOMs and stackoverflow-related bugs in
// the authorizer validation.
func FuzzValidate(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, verb, allowedName string, decision uint8) {
		fdp := gfh.NewConsumer(data)
		req := &admissionv1.AdmissionRequest{}
		err := fdp.GenerateStruct(req)
		if err != nil {
			return
		}
		req.RequestResource.Group = "cert-manager.io"
		req.RequestResource.Resource = "certificaterequests"
		req.RequestSubResource = "status"

		// Add random values to the CR
		cr := &certmanager.CertificateRequest{}
		err = fdp.GenerateStruct(cr)
		if err != nil {
			return
		}
		approvedCR := &certmanager.CertificateRequest{}
		err = fdp.GenerateStruct(approvedCR)
		if err != nil {
			return
		}
		// Add random values to the Group List
		apiGroupList := &metav1.APIGroupList{}
		err = fdp.GenerateStruct(apiGroupList)
		if err != nil {
			return
		}
		// Add random values to the Resource List
		apiResourceList := &metav1.APIResourceList{}
		err = fdp.GenerateStruct(apiResourceList)
		if err != nil {
			return
		}
		// Create an authorizer with random verb and allowedName
		auth := &fakeAuthorizer{
			verb:        verb,
			allowedName: allowedName,
			decision:    authorizer.DecisionAllow,
		}
		// Add a discovery client that returns the Group List
		// and Resource List we created above.
		discoverclient := discoveryfake.NewDiscovery().
			WithServerGroups(func() (*metav1.APIGroupList, error) {
				return apiGroupList, nil
			}).
			WithServerResourcesForGroupVersion(func(groupVersion string) (*metav1.APIResourceList, error) {
				return apiResourceList, nil
			})
		// Create the approval plugin
		a := NewPlugin(auth, discoverclient).(*certificateRequestApproval)
		// Validate
		_, _ = a.Validate(context.Background(), *req, cr, approvedCR)
	})
}
