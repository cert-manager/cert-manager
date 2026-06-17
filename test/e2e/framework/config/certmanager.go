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

package config

import (
	"flag"
)

type CertManager struct {
	// The --cluster-resource-namespace configured for the cert-manager
	// installation
	ClusterResourceNamespace string

	// ServiceAccountName is the name of the Kubernetes ServiceAccount that the
	// cert-manager-controller deployment is using.
	ServiceAccountName string
}

func (c *CertManager) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.ClusterResourceNamespace, "cluster-resource-namespace", "cert-manager", "The --cluster-resource-namespace configured for the cert-manager installation")
	fs.StringVar(&c.ServiceAccountName, "cert-manager-service-account-name", "chart-certmanager-cert-manager", "ServiceAccountName is the name of the Kubernetes ServiceAccount that the cert-manager-controller deployment is using")
}

func (c *CertManager) Validate() []error {
	return nil
}
