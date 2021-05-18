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

package validation

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmacmev1alpha2 "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha2"
	cmacmev1alpha3 "github.com/jetstack/cert-manager/pkg/apis/acme/v1alpha3"
	cmacmev1beta1 "github.com/jetstack/cert-manager/pkg/apis/acme/v1beta1"
	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
)

// This file holds temporary functionality for cert-manager v1.4 API deprecation.
// It will be removed in cert-manager v1.6, when we remove the deprecated APIs.
var (
	deprecatedAPIs = map[string]schema.GroupVersion{
		cmacmev1alpha2.SchemeGroupVersion.String(): cmacme.SchemeGroupVersion,
		cmacmev1alpha3.SchemeGroupVersion.String(): cmacme.SchemeGroupVersion,
		cmacmev1beta1.SchemeGroupVersion.String():  cmacme.SchemeGroupVersion,
	}

	deprecationMessageTemplate = "%s %s is deprecated in v1.4+, unavailable in v1.6+; use %v %s"
)

func validateAPIVersion(gvk metav1.GroupVersionKind) validation.WarningList {
	// There might be a smarter way to get GroupVersion
	gv := fmt.Sprintf("%s/%s", gvk.Group, gvk.Version)
	kind := gvk.Kind
	if newV, ok := deprecatedAPIs[gv]; ok {
		w := fmt.Sprintf(deprecationMessageTemplate, gv, kind, newV, kind)
		return validation.WarningList{w}
	}
	return nil
}
