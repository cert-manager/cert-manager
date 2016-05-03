package ingress

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/util/intstr"
)

func TestIngress_SetGetChallengeEndpoints(t *testing.T) {
	ing := &Ingress{
		IngressApi: &k8sExtensions.Ingress{},
	}

	port := intstr.FromInt(5)

	ing.SetChallengeEndpoints(
		[]string{"test123.com", "456.com"},
		"my-service",
		port,
	)

	domains := ing.GetChallengeEndpoints()

	sort.Strings(domains)

	assert.Equal(t, []string{"456.com", "test123.com"}, domains)

}

func TestIngress_Tls(t *testing.T) {
	ing := &Ingress{
		IngressApi: &k8sExtensions.Ingress{
			Spec: k8sExtensions.IngressSpec{
				TLS: []k8sExtensions.IngressTLS{
					k8sExtensions.IngressTLS{
						Hosts:      []string{"domain1", "domain2"},
						SecretName: "secret1",
					},
					k8sExtensions.IngressTLS{
						Hosts:      []string{"domain3"},
						SecretName: "secret2",
					},
				},
			},
		},
	}

	assert.Equal(t, 2, len(ing.Tls()))

	found := 0

	for _, tls := range ing.Tls() {
		if tls.SecretMetadata().Name == "secret1" {
			found++
			assert.Equal(t, []string{"domain1", "domain2"}, tls.Hosts())
		}
		if tls.SecretMetadata().Name == "secret2" {
			found++
			assert.Equal(t, []string{"domain3"}, tls.Hosts())
		}
	}

	assert.Equal(t, 2, found)
}
