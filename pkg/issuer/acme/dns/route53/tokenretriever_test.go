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

package route53

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestKubernetesServiceAccountTokenRetriever(t *testing.T) {
	t.Run("mints a token for the configured ServiceAccount", func(t *testing.T) {
		fake := kubefake.NewClientset()
		var gotTokenRequest *authv1.TokenRequest
		fake.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
			if action.GetSubresource() != "token" {
				return false, nil, nil
			}
			gotTokenRequest = action.(k8stesting.CreateAction).GetObject().(*authv1.TokenRequest).DeepCopy()
			response := gotTokenRequest.DeepCopy()
			response.Status.Token = "minted-token"
			return true, response, nil
		})

		retriever := &KubernetesServiceAccountTokenRetriever{
			ServiceAccountName: "my-service-account",
			Audiences:          []string{"sts.amazonaws.com"},
			Namespace:          "my-namespace",
			Client:             fake.CoreV1().ServiceAccounts("my-namespace"),
		}

		token, err := retriever.GetIdentityToken()
		require.NoError(t, err)
		assert.Equal(t, []byte("minted-token"), token)
		assert.Equal(t, []string{"sts.amazonaws.com"}, gotTokenRequest.Spec.Audiences)
		assert.Equal(t, int64(600), *gotTokenRequest.Spec.ExpirationSeconds)
	})

	t.Run("wraps TokenRequest errors", func(t *testing.T) {
		fake := kubefake.NewClientset()
		fake.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("simulated error")
		})

		retriever := &KubernetesServiceAccountTokenRetriever{
			ServiceAccountName: "my-service-account",
			Namespace:          "my-namespace",
			Client:             fake.CoreV1().ServiceAccounts("my-namespace"),
		}

		_, err := retriever.GetIdentityToken()
		assert.EqualError(t, err, "failed to request token for my-namespace/my-service-account: simulated error")
	})
}
