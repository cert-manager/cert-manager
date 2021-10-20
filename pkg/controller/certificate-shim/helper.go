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

package shimhelper

import (
	"errors"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

var (
	errNilCertificate           = errors.New("the supplied Certificate pointer was nil")
	errInvalidIngressAnnotation = errors.New("invalid ingress annotation")
)

// translateAnnotations updates the Certificate spec using the ingress-like
// annotations. For example, the following Ingress:
//
//   kind: Ingress
//   metadata:
//     annotations:
//       cert-manager.io/common-name: example.com
//       cert-manager.io/duration: 2160h
//       cert-manager.io/renew-before: 1440h
//       cert-manager.io/usages: "digital signature,key encipherment"
//
// is mapped to the following Certificate:
//
//   kind: Certificate
//   spec:
//     commonName: example.com
//     duration: 2160h
//     renewBefore: 1440h
//     usages:
//       - digital signature
//       - key encipherment
func translateAnnotations(crt *cmapi.Certificate, ingLikeAnnotations map[string]string) error {
	if crt == nil {
		return errNilCertificate
	}

	if commonName, found := ingLikeAnnotations[cmapi.CommonNameAnnotationKey]; found {
		crt.Spec.CommonName = commonName
	}

	if duration, found := ingLikeAnnotations[cmapi.DurationAnnotationKey]; found {
		duration, err := time.ParseDuration(duration)
		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.DurationAnnotationKey, err)
		}
		crt.Spec.Duration = &metav1.Duration{Duration: duration}
	}

	if renewBefore, found := ingLikeAnnotations[cmapi.RenewBeforeAnnotationKey]; found {
		duration, err := time.ParseDuration(renewBefore)
		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.RenewBeforeAnnotationKey, err)
		}
		crt.Spec.RenewBefore = &metav1.Duration{Duration: duration}
	}

	if usages, found := ingLikeAnnotations[cmapi.UsagesAnnotationKey]; found {
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
