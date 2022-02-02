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

// Package ctl was created to have a scheme that has the internal cert-manager types,
// and their conversion functions as well as the List object type registered, which is needed for ctl command like
// `convert` or `create certificaterequest`.

package ctl

import (
	corev1 "k8s.io/api/core/v1"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"

	acmeinstall "github.com/cert-manager/cert-manager/internal/apis/acme/install"
	cminstall "github.com/cert-manager/cert-manager/internal/apis/certmanager/install"
	metainstall "github.com/cert-manager/cert-manager/internal/apis/meta/install"
)

// Define a Scheme that has all cert-manager API types registered, including
// the internal API version, defaulting functions and conversion functions for
// all external versions.

var (
	// Scheme is a Kubernetes runtime.Scheme with all internal and external API
	// versions for cert-manager types registered.
	Scheme = runtime.NewScheme()
)

func init() {
	cminstall.Install(Scheme)
	acmeinstall.Install(Scheme)
	metainstall.Install(Scheme)

	// This is used to add the List object type
	listGroupVersion := schema.GroupVersionKind{Group: "", Version: runtime.APIVersionInternal, Kind: "List"}
	Scheme.AddKnownTypeWithName(listGroupVersion, &metainternalversion.List{})
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})

	utilruntime.Must(kscheme.AddToScheme(Scheme))
	utilruntime.Must(metainternalversion.AddToScheme(Scheme))

	// Adds the conversion between internalmeta.List and corev1.List
	_ = Scheme.AddConversionFunc((*corev1.List)(nil), (*metainternalversion.List)(nil), func(a, b interface{}, scope conversion.Scope) error {
		metaList := &metav1.List{}
		metaList.Items = a.(*corev1.List).Items
		return metainternalversion.Convert_v1_List_To_internalversion_List(metaList, b.(*metainternalversion.List), scope)
	})

	_ = Scheme.AddConversionFunc((*metainternalversion.List)(nil), (*corev1.List)(nil), func(a, b interface{}, scope conversion.Scope) error {
		metaList := &metav1.List{}
		err := metainternalversion.Convert_internalversion_List_To_v1_List(a.(*metainternalversion.List), metaList, scope)
		if err != nil {
			return err
		}
		b.(*corev1.List).Items = metaList.Items
		return nil
	})
}
