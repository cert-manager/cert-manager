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

package controller

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	v1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

// ownersOfCertificate returns references to controllers that are referred to in the
// given Certificate's ownerRef.
func (c *controller) ownersOfCertificate(crt *v1.Certificate) ([]runtime.Object, error) {
	objs, err := c.objectLister.List(labels.NewSelector())

	if err != nil {
		return nil, fmt.Errorf("error listing certificates: %s", err.Error())
	}

	var affected []runtime.Object
	for _, obj := range objs {
		o, ok := obj.(metav1.Object)
		if !ok {
			panic(fmt.Sprintf("object %T is not a metav1.object", obj))
		}
		if crt.Namespace != o.GetNamespace() {
			continue
		}

		if metav1.IsControlledBy(crt, o) {
			affected = append(affected, obj)
		}
	}

	return affected, nil
}
