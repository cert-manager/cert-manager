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

package generic

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
)

func Update(cmClient cmclient.Interface, genericIssuer cmapi.GenericIssuer) (cmapi.GenericIssuer, error) {
	switch genericIssuer.GetObjectKind().GroupVersionKind().Kind {
	case cmapi.IssuerKind:
		issuer, ok := genericIssuer.(*cmapi.Issuer)
		if !ok {
			return nil, fmt.Errorf("failed to assert Issuer with kind %q: %q/%q",
				genericIssuer.GetObjectKind().GroupVersionKind().Kind, genericIssuer.GetNamespace(), genericIssuer.GetName())
		}
		return cmClient.CertmanagerV1alpha2().Issuers(issuer.Namespace).UpdateStatus(context.TODO(), issuer, metav1.UpdateOptions{})

	case cmapi.ClusterIssuerKind:
		clusterIssuer, ok := genericIssuer.(*cmapi.ClusterIssuer)
		if !ok {
			return nil, fmt.Errorf("failed to assert ClusterIssuer with kind %q: %q/%q",
				genericIssuer.GetObjectKind().GroupVersionKind().Kind, genericIssuer.GetNamespace(), genericIssuer.GetName())
		}
		return cmClient.CertmanagerV1alpha2().ClusterIssuers().UpdateStatus(context.TODO(), clusterIssuer, metav1.UpdateOptions{})

	default:
		return nil, fmt.Errorf("unrecognized issuer kind, expecting %q, %q, got %q",
			cmapi.IssuerKind, cmapi.ClusterIssuerKind, genericIssuer.GetObjectKind().GroupVersionKind().Kind)
	}
}
