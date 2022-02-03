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

package controller

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// ResourceNamespace returns the Kubernetes namespace where resources
// created or read by `iss` are located.
func (o IssuerOptions) ResourceNamespace(iss cmapi.GenericIssuer) string {
	ns := iss.GetObjectMeta().Namespace
	if ns == "" {
		ns = o.ClusterResourceNamespace
	}
	return ns
}

// CanUseAmbientCredentials returns whether `iss` will attempt to configure itself
// from ambient credentials (e.g. from a cloud metadata service).
func (o IssuerOptions) CanUseAmbientCredentials(iss cmapi.GenericIssuer) bool {
	switch iss.(type) {
	case *cmapi.ClusterIssuer:
		return o.ClusterIssuerAmbientCredentials
	case *cmapi.Issuer:
		return o.IssuerAmbientCredentials
	}
	return false
}
