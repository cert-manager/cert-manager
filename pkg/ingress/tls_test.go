package ingress

import (
	"testing"

	"github.com/stretchr/testify/assert"
	k8sExtensions "k8s.io/kubernetes/pkg/apis/extensions"
)

func TestTls_Validate(t *testing.T) {
	ing := &Ingress{}
	tlsNoHosts := &Tls{
		IngressTLS: &k8sExtensions.IngressTLS{
			SecretName: "my-secret",
		},
		ingress: ing,
	}

	tlsNoSecretName := &Tls{
		IngressTLS: &k8sExtensions.IngressTLS{
			Hosts: []string{"das.de.de", "k8s.io"},
		},
		ingress: ing,
	}

	tls := &Tls{
		IngressTLS: &k8sExtensions.IngressTLS{
			Hosts:      []string{"das.de.de", "k8s.io"},
			SecretName: "my-secret",
		},
		ingress: ing,
	}

	err := tlsNoHosts.Validate()
	assert.NotNil(t, err, "validate fails with no hosts")

	err = tlsNoSecretName.Validate()
	assert.NotNil(t, err, "validate fails with no secret")

	err = tls.Validate()
	assert.Nil(t, err, "validates correct tls")

}
