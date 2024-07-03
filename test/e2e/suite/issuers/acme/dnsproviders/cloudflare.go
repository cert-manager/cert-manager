/*
Copyright 2020 The cert-manager Authors.

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
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/addon/base"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/config"
	"github.com/cert-manager/cert-manager/e2e-tests/framework/util/errors"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
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

func (b *Cloudflare) Setup(c *config.Config, _ ...addon.AddonTransferableData) (addon.AddonTransferableData, error) {
	if c.Suite.ACME.Cloudflare.APIKey == "" ||
		c.Suite.ACME.Cloudflare.Domain == "" ||
		c.Suite.ACME.Cloudflare.Email == "" {
		return nil, errors.NewSkip(ErrNoCredentials)
	}

	if b.Base == nil {
		b.Base = &base.Base{}
		_, err := b.Base.Setup(c)
		if err != nil {
			return nil, err
		}
	}

	b.cf = c.Suite.ACME.Cloudflare

	return nil, nil
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

	s, err := b.Base.Details().KubeClient.CoreV1().Secrets(b.Namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	b.createdSecret = s
	b.details.ProviderConfig = cmacme.ACMEChallengeSolverDNS01{
		Cloudflare: &cmacme.ACMEIssuerDNS01ProviderCloudflare{
			Email: b.cf.Email,
			APIKey: &cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{
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
	return b.Base.Details().KubeClient.CoreV1().Secrets(b.createdSecret.Namespace).Delete(context.TODO(), b.createdSecret.Name, metav1.DeleteOptions{})
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
