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

type VenafiCloud struct {
	Base   *base.Base
	config *config.Config

	// Namespace to create supporting credential resources in
	Namespace string

	details CloudDetails

	createdSecret *corev1.Secret
}

type CloudDetails struct {
	issuerTemplate cmapi.VenafiIssuer
}

func (v *VenafiCloud) Setup(cfg *config.Config) error {
	v.config = cfg

	if v.Base == nil {
		v.Base = &base.Base{}
		err := v.Base.Setup(cfg)
		if err != nil {
			return err
		}
	}

	if v.config.Addons.Venafi.Cloud.Zone == "" {
		return errors.NewSkip(fmt.Errorf("Venafi Cloud Zone must be set"))
	}
	if v.config.Addons.Venafi.Cloud.APIToken == "" {
		return errors.NewSkip(fmt.Errorf("Venafi Cloud APIToken must be set"))
	}

	return nil
}

func (v *VenafiCloud) Provision() error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cm-e2e-venafi-cloud-",
			Namespace:    v.Namespace,
		},
		Data: map[string][]byte{
			"apikey": []byte(v.config.Addons.Venafi.Cloud.APIToken),
		},
	}

	s, err := v.Base.Details().KubeClient.CoreV1().Secrets(v.Namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	v.createdSecret = s
	v.details.issuerTemplate = cmapi.VenafiIssuer{
		Zone: v.config.Addons.Venafi.Cloud.Zone,
		Cloud: &cmapi.VenafiCloud{
			URL: "https://api.venafi.cloud",
			APITokenSecretRef: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{
					Name: s.Name,
				},
				Key: "apikey",
			},
		},
	}
	return nil
}

func (v *VenafiCloud) Details() *CloudDetails {
	return &v.details
}

func (v *VenafiCloud) Deprovision() error {
	return v.Base.Details().KubeClient.CoreV1().Secrets(v.createdSecret.Namespace).Delete(context.TODO(), v.createdSecret.Name, metav1.DeleteOptions{})
}

func (v *VenafiCloud) SupportsGlobal() bool {
	return true
}

func (t *CloudDetails) BuildIssuer() *cmapi.Issuer {
	return &cmapi.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "venafi-cloud-",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				Venafi: &t.issuerTemplate,
			},
		},
	}
}

func (t *CloudDetails) BuildClusterIssuer() *cmapi.ClusterIssuer {
	return &cmapi.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "venafi-cloud-",
		},
		Spec: cmapi.IssuerSpec{
			IssuerConfig: cmapi.IssuerConfig{
				Venafi: &t.issuerTemplate,
			},
		},
	}
}

// SetAPIKey sets the Secret data["apikey"] value
func (v *VenafiCloud) SetAPIKey(token string) error {
	v.createdSecret.Data["apikey"] = []byte(token)
	s, err := v.Base.Details().KubeClient.CoreV1().Secrets(v.Namespace).Update(context.TODO(), v.createdSecret, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	v.createdSecret = s
	return nil
}
