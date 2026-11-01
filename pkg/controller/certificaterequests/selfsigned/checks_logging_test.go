/*
Copyright The cert-manager Authors.

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

package selfsigned

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	cmdoc "github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientv1 "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

// Keep the resolvable issuer first, independently of the indexer's map order.
type orderedCertificateRequestLister struct {
	clientv1.CertificateRequestLister
}

func (l orderedCertificateRequestLister) CertificateRequests(namespace string) clientv1.CertificateRequestNamespaceLister {
	return orderedCertificateRequestNamespaceLister{
		CertificateRequestNamespaceLister: l.CertificateRequestLister.CertificateRequests(namespace),
	}
}

type orderedCertificateRequestNamespaceLister struct {
	clientv1.CertificateRequestNamespaceLister
}

func (l orderedCertificateRequestNamespaceLister) List(selector labels.Selector) ([]*cmapi.CertificateRequest, error) {
	requests, err := l.CertificateRequestNamespaceLister.List(selector)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(requests, func(a, b *cmapi.CertificateRequest) int {
		return strings.Compare(a.Name, b.Name)
	})
	return requests, nil
}

func Test_certificateRequestsForSecret_loggingContext(t *testing.T) {
	tests := []struct {
		name        string
		issuerRef   cmmeta.IssuerReference
		skipMessage string
	}{
		{
			name: "missing issuer",
			issuerRef: cmmeta.IssuerReference{
				Name: "missing", Kind: "Issuer", Group: cmdoc.GroupName,
			},
			skipMessage: "issuer not found, skipping",
		},
		{
			name: "external issuer group",
			issuerRef: cmmeta.IssuerReference{
				Name: "external", Kind: "Issuer", Group: "external.example.com",
			},
			skipMessage: "skipping SelfSigned secret reference checks since issuer has external group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const namespace = "test-namespace"
			secret := gen.Secret("test-secret", gen.SetSecretNamespace(namespace))
			first := gen.CertificateRequest("1-existing",
				gen.SetCertificateRequestNamespace(namespace),
				gen.SetCertificateRequestIssuer(cmmeta.IssuerReference{
					Name: "existing", Kind: "Issuer", Group: cmdoc.GroupName,
				}),
				gen.SetCertificateRequestAnnotations(map[string]string{
					cmapi.CertificateRequestPrivateKeyAnnotationKey: secret.Name,
				}),
			)
			skipped := gen.CertificateRequest("2-skipped",
				gen.SetCertificateRequestNamespace(namespace),
				gen.SetCertificateRequestIssuer(tt.issuerRef),
			)

			requestIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
				cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
			})
			require.NoError(t, requestIndexer.Add(first))
			require.NoError(t, requestIndexer.Add(skipped))
			lister := orderedCertificateRequestLister{
				CertificateRequestLister: clientv1.NewCertificateRequestLister(requestIndexer),
			}

			issuerIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
				cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
			})
			require.NoError(t, issuerIndexer.Add(gen.Issuer("existing",
				gen.SetIssuerNamespace(namespace),
				gen.SetIssuerSelfSigned(cmapi.SelfSignedIssuer{}),
			)))
			helper := issuer.NewHelper(
				clientv1.NewIssuerLister(issuerIndexer),
				clientv1.NewClusterIssuerLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})),
			)

			var entries []map[string]any
			logger := funcr.NewJSON(func(line string) {
				var entry map[string]any
				require.NoError(t, json.Unmarshal([]byte(line), &entry))
				entries = append(entries, entry)
			}, funcr.Options{Verbosity: logf.DebugLevel})

			affected, err := certificateRequestsForSecret(logf.WithResource(logger, secret), lister, helper, secret)
			require.NoError(t, err)
			assert.Equal(t, []*cmapi.CertificateRequest{first}, affected)

			var issuerEntries, skipEntries []map[string]any
			issuerPosition, skipPosition := -1, -1
			for i, entry := range entries {
				switch entry["msg"] {
				case "ensuring issuer type matches this controller":
					issuerEntries = append(issuerEntries, entry)
					issuerPosition = i
				case tt.skipMessage:
					skipEntries = append(skipEntries, entry)
					skipPosition = i
				}
			}

			// Prove the issuer was logged before the skip; no output must not pass.
			require.Len(t, issuerEntries, 1)
			require.Len(t, skipEntries, 1)
			assert.Less(t, issuerPosition, skipPosition)
			assert.Equal(t, "existing", issuerEntries[0][logf.RelatedResourceNameKey])
			assert.Equal(t, namespace, issuerEntries[0][logf.RelatedResourceNamespaceKey])
			assert.Equal(t, "Issuer", issuerEntries[0][logf.RelatedResourceKindKey])
			assert.Equal(t, "v1", issuerEntries[0][logf.RelatedResourceVersionKey])

			// Preserve the Secret context without inheriting the previous issuer.
			assert.Equal(t, secret.Name, skipEntries[0][logf.ResourceNameKey])
			for _, key := range []string{
				logf.RelatedResourceNameKey,
				logf.RelatedResourceNamespaceKey,
				logf.RelatedResourceKindKey,
				logf.RelatedResourceVersionKey,
			} {
				assert.NotContains(t, skipEntries[0], key, "skip log contains stale issuer context")
			}
		})
	}
}
