/*
Copyright 2020 The Jetstack cert-manager contributors.

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

package defaults

import cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

const (
	DefaultCloudAPITokenSecretRefKey = "api-key"
	DefaultClientID                  = "cert-manager"
)

func SetDefaults_Issuer(issuer *cmapi.Issuer) {
	if issuer.Spec.Venafi == nil {
		return
	}
	SetDefaults_VenafiIssuer(issuer.Spec.Venafi)
}

func SetDefaults_ClusterIssuer(issuer *cmapi.ClusterIssuer) {
	if issuer.Spec.Venafi == nil {
		return
	}
	SetDefaults_VenafiIssuer(issuer.Spec.Venafi)
}

func SetDefaults_VenafiIssuer(issuer *cmapi.VenafiIssuer) {
	if issuer.Cloud == nil {
		return
	}
	if issuer.Cloud.APITokenSecretRef.Key == "" {
		issuer.Cloud.APITokenSecretRef.Key = DefaultCloudAPITokenSecretRefKey
	}
}
