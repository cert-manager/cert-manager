/*
Copyright 2026 The cert-manager Authors.

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

package certificates

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	internalcertificates "github.com/cert-manager/cert-manager/internal/controller/certificates"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
)

// applyCertificateStatus server-side applies the given status fields to the
// named Certificate under fieldManager, forcing ownership of only those fields.
// On master this helper lives in status_scalar_apply_test.go.
func applyCertificateStatus(t *testing.T, cmClient cmclient.Interface, fieldManager, namespace, name string, status cmapi.CertificateStatus) {
	t.Helper()
	require.NoError(t, internalcertificates.ApplyStatus(t.Context(), cmClient, fieldManager, &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status:     status,
	}))
}
