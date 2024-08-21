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

package certificatesigningrequests

import (
	"fmt"

	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/certificatesigningrequests/util"
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
	crs, err := c.certificateSigningRequestsForGenericIssuer(iss)
	if err != nil {
		log.Error(err, "error looking up certificate signing requests observing issuer or clusterissuer")
		return
	}
	for _, cr := range crs {
		c.queue.Add(types.NamespacedName{
			Name:      cr.Name,
			Namespace: cr.Namespace,
		})
	}
}

func (c *Controller) certificateSigningRequestsForGenericIssuer(iss cmapi.GenericIssuer) ([]*certificatesv1.CertificateSigningRequest, error) {
	csrs, err := c.csrLister.List(labels.NewSelector())
	if err != nil {
		return nil, fmt.Errorf("error listing certificates signing requests: %s", err.Error())
	}

	_, isClusterIssuer := iss.(*cmapi.ClusterIssuer)

	var affected []*certificatesv1.CertificateSigningRequest
	for _, csr := range csrs {
		ref, ok := util.SignerIssuerRefFromSignerName(csr.Spec.SignerName)

		switch {
		case !ok,
			ref.Group != certmanager.GroupName,
			iss.GetNamespace() != ref.Namespace,
			iss.GetName() != ref.Name,
			isClusterIssuer && ref.Type != "clusterissuers",
			!isClusterIssuer && ref.Type != "issuers":
			continue
		}

		affected = append(affected, csr)
	}

	return affected, nil
}
