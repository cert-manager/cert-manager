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
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1alpha2"
)

// IssuerLister is used to list issuers that are either Issuers or
// ClusterIssuers.
type IssuerLister interface {
	Get(namespace, name string) (cmapi.GenericIssuer, error)
}

// implementation of generic lister for Issuers and ClusterIssuers
type issuerLister struct {
	cmlisters.IssuerLister
}
type clusterIssuerLister struct {
	cmlisters.ClusterIssuerLister
}

func NewIssuerLister(lister cmlisters.IssuerLister) IssuerLister {
	return &issuerLister{lister}
}

func (i *issuerLister) Get(namespace, name string) (cmapi.GenericIssuer, error) {
	return i.IssuerLister.Issuers(namespace).Get(name)
}

func NewClusterIssuerLister(lister cmlisters.ClusterIssuerLister) IssuerLister {
	return &clusterIssuerLister{lister}
}

func (i *clusterIssuerLister) Get(_, name string) (cmapi.GenericIssuer, error) {
	return i.ClusterIssuerLister.Get(name)
}
