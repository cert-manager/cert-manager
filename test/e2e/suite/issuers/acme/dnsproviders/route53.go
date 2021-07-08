/*
Copyright 2021 The cert-manager Authors.

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
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/base"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/util/errors"
)

type Route53 struct {
	Base       *base.Base
	Namespace  string
	details    Details
	nameserver string

	accessKeyID     string
	secretAccessKey string
	config          *config.Config
	secret          *corev1.Secret
}

func (r *Route53) Setup(c *config.Config) error {
	// Only run route53 tests if the test config flag --dns-provider is set to route-53
	if c.Addons.ACMEServer.DNSProvider != "route-53" {
		return errors.NewSkip(
			fmt.Errorf("skipping Route53 tests as DNS provider is set to %s",
				c.Addons.ACMEServer.DNSProvider),
		)
	}

	// If we have no credentials we can't run the tests.
	r.accessKeyID = os.Getenv("AWS_ACCESS_KEY_ID")
	r.secretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	if len(r.accessKeyID) == 0 || len(r.secretAccessKey) == 0 {
		return errors.NewSkip(
			fmt.Errorf("skipping AWS tests as no credentials were found (set $AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY)"),
		)
	}

	if r.Base == nil {
		r.Base = &base.Base{}
		err := r.Base.Setup(c)
		if err != nil {
			return err
		}
	}

	r.nameserver = c.Addons.ACMEServer.DNSServer
	r.details.BaseDomain = c.Addons.IngressController.Domain
	r.details.ProviderConfig = cmacme.ACMEChallengeSolverDNS01{
		Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
			HostedZoneID: c.Addons.ACMEServer.Route53Zone,
			Region:       c.Addons.ACMEServer.Route53Region,
		},
	}
	return nil
}

// Provision will create a copy of the DNS provider credentials in a secret in
// the APIServer, and return a portion of an Issuer that can be used to
// utilise these credentials in tests.
func (r *Route53) Provision() error {
	if len(r.Namespace) == 0 {
		return fmt.Errorf("route53: namespace must be set")
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-e2e-route53-",
			Namespace:    r.Namespace,
		},
		Data: map[string][]byte{
			"AWS_SECRET_ACCESS_KEY": []byte(r.secretAccessKey),
		},
	}

	s, err := r.Base.Details().KubeClient.CoreV1().Secrets(r.Namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	r.secret = s

	r.nameserver = r.config.Addons.ACMEServer.DNSServer
	r.details.BaseDomain = r.config.Addons.IngressController.Domain
	r.details.ProviderConfig = cmacme.ACMEChallengeSolverDNS01{
		Route53: &cmacme.ACMEIssuerDNS01ProviderRoute53{
			HostedZoneID: r.config.Addons.ACMEServer.Route53Zone,
			Region:       r.config.Addons.ACMEServer.Route53Region,
			AccessKeyID:  r.accessKeyID,
			SecretAccessKey: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{Name: s.Name},
				Key:                  "AWS_SECRET_ACCESS_KEY",
			},
		},
	}
	return nil
}

func (r *Route53) Deprovision() error {
	if len(r.Namespace) == 0 {
		return fmt.Errorf("route53: namespace must be set")
	}
	return r.Base.Details().KubeClient.CoreV1().Secrets(r.Namespace).Delete(context.TODO(), r.secret.Name, metav1.DeleteOptions{})
}

func (r *Route53) Details() *Details {
	return &r.details
}

func (r *Route53) SupportsGlobal() bool {
	return false
}
