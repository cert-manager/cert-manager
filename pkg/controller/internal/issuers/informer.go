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
	"k8s.io/client-go/tools/cache"

	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions/certmanager/v1"
)

// TODO:
type Informer interface {
	Informer() cache.SharedIndexInformer
	Lister() Lister
}

type issuerInformer struct {
	informer cminformers.IssuerInformer
}
type clusterIssuerInformer struct {
	informer cminformers.ClusterIssuerInformer
}

func NewIssuerInformer(informer cminformers.IssuerInformer) Informer {
	return &issuerInformer{informer}
}

func (i *issuerInformer) Lister() Lister {
	return NewIssuerLister(i.informer.Lister())
}

func (i *issuerInformer) Informer() cache.SharedIndexInformer {
	return i.informer.Informer()
}

func NewClusterIssuerInformer(informer cminformers.ClusterIssuerInformer) Informer {
	return &clusterIssuerInformer{informer}
}

func (c *clusterIssuerInformer) Lister() Lister {
	return NewClusterIssuerLister(c.informer.Lister())
}

func (c *clusterIssuerInformer) Informer() cache.SharedIndexInformer {
	return c.informer.Informer()
}
