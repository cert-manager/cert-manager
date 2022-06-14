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

package venafi

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/e2e/framework/addon/base"
	"github.com/cert-manager/cert-manager/test/e2e/framework/config"
	"github.com/cert-manager/cert-manager/test/e2e/framework/util/errors"
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
		return errors.NewSkip(fmt.Errorf("Venafi TPP URL must be set"))
	}
	if v.config.Addons.Venafi.TPP.Zone == "" {
		return errors.NewSkip(fmt.Errorf("Venafi TPP Zone must be set"))
	}

	if v.config.Addons.Venafi.TPP.AccessToken == "" {
		if v.config.Addons.Venafi.TPP.Username == "" {
			return errors.NewSkip(fmt.Errorf("Venafi TPP requires either an access-token or username-password to be set: missing username"))
		}
		if v.config.Addons.Venafi.TPP.Password == "" {
			return errors.NewSkip(fmt.Errorf("Venafi TPP requires either an access-token or username-password to be set: missing password"))
		}
	}

	return nil
}

func (v *VenafiTPP) Provision() error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-e2e-venafi-",
			Namespace:    v.Namespace,
		},
		Data: map[string][]byte{
			"username":     []byte(v.config.Addons.Venafi.TPP.Username),
			"password":     []byte(v.config.Addons.Venafi.TPP.Password),
			"access-token": []byte(v.config.Addons.Venafi.TPP.AccessToken),
		},
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

// SetAccessToken sets the Secret data["access-token"] value
func (v *VenafiTPP) SetAccessToken(token string) error {
	v.createdSecret.Data["access-token"] = []byte(token)
	s, err := v.Base.Details().KubeClient.CoreV1().Secrets(v.Namespace).Update(context.TODO(), v.createdSecret, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	v.createdSecret = s
	return nil
}
