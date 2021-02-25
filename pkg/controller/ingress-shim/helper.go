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

package controller

import (
	"errors"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

var (
	errNilCertificate           = errors.New("the supplied Certificate pointer was nil")
	errInvalidIngressAnnotation = errors.New("invalid ingress annotation")
)

func translateIngressAnnotations(crt *cmapi.Certificate, annotations map[string]string) error {
	if crt == nil {
		return errNilCertificate
	}
	if commonName, found := annotations[cmapi.CommonNameAnnotationKey]; found {
		crt.Spec.CommonName = commonName
	}
	if duration, found := annotations[cmapi.DurationAnnotationKey]; found {
		duration, err := time.ParseDuration(duration)
		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.DurationAnnotationKey, err)
		}
		crt.Spec.Duration = &metav1.Duration{Duration: duration}
	}
	if renewBefore, found := annotations[cmapi.RenewBeforeAnnotationKey]; found {
		duration, err := time.ParseDuration(renewBefore)
		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.RenewBeforeAnnotationKey, err)
		}
		crt.Spec.RenewBefore = &metav1.Duration{Duration: duration}
	}
	if usages, found := annotations[cmapi.UsagesAnnotationKey]; found {
		var newUsages []cmapi.KeyUsage
		for _, usageName := range strings.Split(usages, ",") {
			usage := cmapi.KeyUsage(strings.Trim(usageName, " "))
			_, isKU := apiutil.KeyUsageType(usage)
			_, isEKU := apiutil.ExtKeyUsageType(usage)
			if !isKU && !isEKU {
				return fmt.Errorf("%w %q: invalid key usage name %q", errInvalidIngressAnnotation, cmapi.UsagesAnnotationKey, usageName)
			}
			newUsages = append(newUsages, usage)
		}
		crt.Spec.Usages = newUsages
	}
	return nil
}
