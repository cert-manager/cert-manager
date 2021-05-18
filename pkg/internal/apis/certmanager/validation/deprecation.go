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

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmapiv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmapiv1alpha3 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha3"
	cmapiv1beta1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	"github.com/jetstack/cert-manager/pkg/internal/api/validation"
)

// This file holds temporary functionality for cert-manager v1.4 API deprecation.
// It will be removed in cert-manager v1.6, when we remove the deprecated APIs.
var (
	deprecatedAPIs = map[string]schema.GroupVersion{
		cmapiv1alpha2.SchemeGroupVersion.String(): cmapi.SchemeGroupVersion,
		cmapiv1alpha3.SchemeGroupVersion.String(): cmapi.SchemeGroupVersion,
		cmapiv1beta1.SchemeGroupVersion.String():  cmapi.SchemeGroupVersion,
	}

	deprecationMessageTemplate = "%s %s is deprecated in v1.4+, unavailable in v1.6+; use %v %s"
)

func validateAPIVersion(gvk v1.GroupVersionKind) validation.WarningList {
	// There might be a smarter way to get GroupVersion
	gv := fmt.Sprintf("%s/%s", gvk.Group, gvk.Version)
	kind := gvk.Kind
	if newV, ok := deprecatedAPIs[gv]; ok {
		w := fmt.Sprintf(deprecationMessageTemplate, gv, kind, newV, kind)
		return validation.WarningList{w}
	}
	return nil
}
