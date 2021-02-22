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

package issuers

import (
	"k8s.io/apimachinery/pkg/labels"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
)

// TODO:
// Lister is used to list issuers that are either Issuers or
// ClusterIssuers.
type Lister interface {
	Get(namespace, name string) (cmapi.GenericIssuer, error)
	List(labels.Selector) ([]cmapi.GenericIssuer, error)
}

// implementation of generic lister for Issuers and ClusterIssuers
type issuerLister struct {
	cmlisters.IssuerLister
}
type clusterIssuerLister struct {
	cmlisters.ClusterIssuerLister
}

func NewIssuerLister(lister cmlisters.IssuerLister) Lister {
	return &issuerLister{lister}
}

func (i *issuerLister) Get(namespace, name string) (cmapi.GenericIssuer, error) {
	return i.IssuerLister.Issuers(namespace).Get(name)
}

func (i *issuerLister) List(selector labels.Selector) ([]cmapi.GenericIssuer, error) {
	issuers, err := i.IssuerLister.List(selector)
	if err != nil {
		return nil, err
	}

	var gissuers []cmapi.GenericIssuer
	for _, iss := range issuers {
		gissuers = append(gissuers, iss)
	}

	return gissuers, nil
}

func NewClusterIssuerLister(lister cmlisters.ClusterIssuerLister) Lister {
	return &clusterIssuerLister{lister}
}

func (i *clusterIssuerLister) Get(_, name string) (cmapi.GenericIssuer, error) {
	return i.ClusterIssuerLister.Get(name)
}

func (i *clusterIssuerLister) List(selector labels.Selector) ([]cmapi.GenericIssuer, error) {
	issuers, err := i.ClusterIssuerLister.List(selector)
	if err != nil {
		return nil, err
	}

	var gissuers []cmapi.GenericIssuer
	for _, iss := range issuers {
		gissuers = append(gissuers, iss)
	}

	return gissuers, nil
}
