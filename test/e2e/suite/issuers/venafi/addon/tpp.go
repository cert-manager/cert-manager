/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package addon

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/base"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	"github.com/jetstack/cert-manager/test/e2e/framework/util/errors"
)

type VenafiTPP struct {
	Base   *base.Base
	config *config.Config

	// Namespace to create supporting credential resources in
	Namespace string

	details TPPDetails

	createdSecret *corev1.Secret
}

type TPPDetails struct {
	issuerTemplate cmapi.VenafiIssuer
}

func (v *VenafiTPP) Setup(cfg *config.Config) error {
	v.config = cfg

	if v.Base == nil {
		v.Base = &base.Base{}
		err := v.Base.Setup(cfg)
		if err != nil {
			return err
		}
	}

	if v.config.Addons.Venafi.TPP.URL == "" {
		return errors.NewSkip(fmt.Errorf("VENAFI_TPP_URL must be set"))
	}

	return nil
}

func (v *VenafiTPP) Provision() error {
	data := map[string]string{}

	if v.config.Addons.Venafi.TPP.UseOauth {
		var emptyTrustCertPool *x509.CertPool
		c, err := tpp.NewConnector(
			v.config.Addons.Venafi.TPP.URL,
			v.config.Addons.Venafi.TPP.Zone,
			false,
			emptyTrustCertPool,
		)
		if err != nil {
			return fmt.Errorf("error creating TPP client: %v", err)
		}
		resp, err := c.GetRefreshToken(&endpoint.Authentication{
			User:     v.config.Addons.Venafi.TPP.Username,
			Password: v.config.Addons.Venafi.TPP.Password,
			ClientId: "cert-manager",
			Scope:    "certificate:manage,revoke",
		})
		if err != nil {
			return fmt.Errorf("error getting refresh token: %v", err)
		}
		// data["access-token"] = resp.Access_token
		// data["expires"] = strconv.Itoa(resp.Expires)
		data["refresh-token"] = resp.Refresh_token
	} else {
		data["username"] = v.config.Addons.Venafi.TPP.Username
		data["password"] = v.config.Addons.Venafi.TPP.Password
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-e2e-venafi-",
			Namespace:    v.Namespace,
		},
		StringData: data,
	}

	s, err := v.Base.Details().KubeClient.CoreV1().Secrets(v.Namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	v.createdSecret = s
	v.details.issuerTemplate = cmapi.VenafiIssuer{
		Zone: v.config.Addons.Venafi.TPP.Zone,
		TPP: &cmapi.VenafiTPP{
			URL: v.config.Addons.Venafi.TPP.URL,
			CredentialsRef: cmmeta.LocalObjectReference{
				Name: s.Name,
			},
		},
	}
	return nil
}

func (v *VenafiTPP) Details() *TPPDetails {
	return &v.details
}

func (v *VenafiTPP) Deprovision() error {
	return v.Base.Details().KubeClient.CoreV1().Secrets(v.createdSecret.Namespace).Delete(context.TODO(), v.createdSecret.Name, metav1.DeleteOptions{})
}

func (v *VenafiTPP) SupportsGlobal() bool {
	return true
}

func (t *TPPDetails) BuildIssuer() *cmapi.Issuer {
	return &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "venafi-tpp-",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				Venafi: &t.issuerTemplate,
			},
		},
	}
}

func (t *TPPDetails) BuildClusterIssuer() *cmapi.ClusterIssuer {
	return &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "venafi-tpp-",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				Venafi: &t.issuerTemplate,
			},
		},
	}
}
