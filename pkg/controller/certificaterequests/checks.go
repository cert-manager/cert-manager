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

package certificaterequests

import (
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func (c *Controller) handleGenericIssuer(obj interface{}) {
	log := c.log.WithName("handleGenericIssuer")

	iss, ok := obj.(cmapi.GenericIssuer)
	if !ok {
		log.Error(nil, "object does not implement GenericIssuer")
		return
	}

	log = logf.WithResource(log, iss)
	crs, err := c.certificatesRequestsForGenericIssuer(iss)
	if err != nil {
		log.Error(err, "error looking up certificates observing issuer or clusterissuer")
		return
	}
	for _, cr := range crs {
		c.queue.Add(types.NamespacedName{
			Name:      cr.Name,
			Namespace: cr.Namespace,
		})
	}
}

func (c *Controller) certificatesRequestsForGenericIssuer(iss cmapi.GenericIssuer) ([]*cmapi.CertificateRequest, error) {
	crts, err := c.certificateRequestLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificates: %s", err.Error())
	}

	_, isClusterIssuer := iss.(*cmapi.ClusterIssuer)

	var affected []*cmapi.CertificateRequest
	for _, crt := range crts {
		if isClusterIssuer && crt.Spec.IssuerRef.Kind != cmapi.ClusterIssuerKind {
			continue
		}
		if !isClusterIssuer {
			if crt.Namespace != iss.GetObjectMeta().Namespace {
				continue
			}
		}
		if crt.Spec.IssuerRef.Name != iss.GetObjectMeta().Name {
			continue
		}
		affected = append(affected, crt)
	}

	return affected, nil
}
