/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package dnsproviders

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/base"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/util/errors"
)

// Cloudflare provisions cloudflare credentials in a namespace for cert-manager
// to use.
// It also provides a configuration structure that can be used on issuers created
// during tests
type Cloudflare struct {
	Base *base.Base

	Namespace string

	cf      config.Cloudflare
	details Details

	createdSecret *corev1.Secret
}

func (b *Cloudflare) Setup(c *config.Config) error {
	if c.Suite.ACME.Cloudflare.APIKey == "" ||
		c.Suite.ACME.Cloudflare.Domain == "" ||
		c.Suite.ACME.Cloudflare.Email == "" {
		return errors.NewSkip(ErrNoCredentials)
	}

	if b.Base == nil {
		b.Base = &base.Base{}
		err := b.Base.Setup(c)
		if err != nil {
			return err
		}
	}

	b.cf = c.Suite.ACME.Cloudflare

	return nil
}

// Provision will create a copy of the DNS provider credentials in a secret in
// the APIServer, and return a portion of an Issuer that can be used to
// utilise these credentials in tests.
func (b *Cloudflare) Provision() error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-e2e-cloudflare-",
			Namespace:    b.Namespace,
		},
		Data: map[string][]byte{
			"email":   []byte(b.cf.Email),
			"api-key": []byte(b.cf.APIKey),
		},
	}

	s, err := b.Base.Details().KubeClient.CoreV1().Secrets(b.Namespace).Create(secret)
	if err != nil {
		return err
	}

	b.createdSecret = s
	b.details.ProviderConfig = cmapi.ACMEIssuerDNS01Provider{
		Name: "dummy-provider",
		Cloudflare: &cmapi.ACMEIssuerDNS01ProviderCloudflare{
			Email: b.cf.Email,
			APIKey: cmapi.SecretKeySelector{
				LocalObjectReference: cmapi.LocalObjectReference{
					Name: b.createdSecret.Name,
				},
				Key: "api-key",
			},
		},
	}
	b.details.BaseDomain = b.cf.Domain

	return nil
}

func (b *Cloudflare) Deprovision() error {
	b.Base.Details().KubeClient.CoreV1().Secrets(b.createdSecret.Namespace).Delete(b.createdSecret.Name, nil)
	return nil
}

func (b *Cloudflare) Details() *Details {
	return &b.details
}

func (b *Cloudflare) SupportsGlobal() bool {
	return false
}

func (b *Cloudflare) SetNamespace(s string) {
	b.Namespace = s
}
