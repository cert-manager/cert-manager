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
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceAccountTokenCreator is the subset of the Kubernetes ServiceAccount
// client used to mint ServiceAccount tokens.
type ServiceAccountTokenCreator interface {
	CreateToken(ctx context.Context, serviceAccountName string, tokenRequest *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error)
}

// KubernetesServiceAccountTokenRetriever mints a short-lived ServiceAccount
// token using the Kubernetes TokenRequest API. The AWS SDK calls
// GetIdentityToken whenever it (re-)assumes the role with web identity, so
// each role assumption uses a freshly minted token rather than one minted
// when the challenge solver was constructed.
type KubernetesServiceAccountTokenRetriever struct {
	ServiceAccountName string
	Audiences          []string
	Namespace          string
	Client             ServiceAccountTokenCreator
}

var _ stscreds.IdentityTokenRetriever = &KubernetesServiceAccountTokenRetriever{}

// GetIdentityToken implements stscreds.IdentityTokenRetriever, which has no
// context parameter, so the TokenRequest is made with a background context.
func (o *KubernetesServiceAccountTokenRetriever) GetIdentityToken() ([]byte, error) {
	tokenrequest, err := o.Client.CreateToken(context.Background(), o.ServiceAccountName, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         o.Audiences,
			ExpirationSeconds: new(int64(600)),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to request token for %s/%s: %w", o.Namespace, o.ServiceAccountName, err)
	}

	return []byte(tokenrequest.Status.Token), nil
}
