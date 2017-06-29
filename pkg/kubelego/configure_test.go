package kubelego

import (
	"testing"

	"github.com/munnerz/cert-manager/pkg/kubelego_const"

	"github.com/stretchr/testify/assert"
	k8sApi "k8s.io/client-go/pkg/api/v1"
)

type mockTls struct {
	SecretName  string
	IngressName string
	Namespace   string
	hosts       []string
}

func (m *mockTls) Hosts() []string {
	return m.hosts
}

func (m *mockTls) SecretMetadata() *k8sApi.ObjectMeta {
	return &k8sApi.ObjectMeta{
		Name:      m.SecretName,
		Namespace: m.Namespace,
	}
}

func (m *mockTls) IngressMetadata() *k8sApi.ObjectMeta {
	return &k8sApi.ObjectMeta{
		Name:      m.IngressName,
		Namespace: m.Namespace,
	}
}

func (m *mockTls) Process() error {
	// processes a lot
	return nil
}

func getTlsExample() []kubelego.Tls {
	return []kubelego.Tls{
		&mockTls{
			SecretName:  "secret1",
			IngressName: "ingress1",
			Namespace:   "namespace1",
			hosts:       []string{"domain1"},
		},
		&mockTls{
			SecretName:  "secret2",
			IngressName: "ingress2",
			Namespace:   "namespace1",
			hosts:       []string{"domain2"},
		},
		&mockTls{
			SecretName:  "secret1",
			IngressName: "ingress3",
			Namespace:   "namespace2",
			hosts:       []string{"domain3", "domain4"},
		},
		&mockTls{
			SecretName:  "secret1",
			IngressName: "ingress4",
			Namespace:   "namespace1",
			hosts:       []string{"domain1"},
		},
	}
}

func TestKubeLego_TlsIgnoreDuplicatedSecrets(t *testing.T) {
	k := New("test")
	input := getTlsExample()
	output := k.TlsIgnoreDuplicatedSecrets(input)
	assert.EqualValues(t, 2, len(output))
}
