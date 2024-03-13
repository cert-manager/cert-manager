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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/util"
)

var (
	errNilCertificate           = errors.New("the supplied Certificate pointer was nil")
	errInvalidIngressAnnotation = errors.New("invalid ingress annotation")
)

// translateAnnotations updates the Certificate spec using the ingress-like
// annotations. For example, the following Ingress:
//
//	kind: Ingress
//	metadata:
//	  annotations:
//	    cert-manager.io/common-name: example.com
//	    cert-manager.io/duration: 2160h
//	    cert-manager.io/renew-before: 1440h
//	    cert-manager.io/usages: "digital signature,key encipherment"
//	    cert-manager.io/revision-history-limit: 7
//
// is mapped to the following Certificate:
//
//	kind: Certificate
//	spec:
//	  commonName: example.com
//	  duration: 2160h
//	  renewBefore: 1440h
//	  usages:
//	    - digital signature
//	    - key encipherment
//	  revisionHistoryLimit: 7
func translateAnnotations(crt *cmapi.Certificate, ingLikeAnnotations map[string]string) error {
	if crt == nil {
		return errNilCertificate
	}

	if commonName, found := ingLikeAnnotations[cmapi.CommonNameAnnotationKey]; found {
		crt.Spec.CommonName = commonName
	}

	if emailAddresses, found := ingLikeAnnotations[cmapi.EmailsAnnotationKey]; found {
		crt.Spec.EmailAddresses = strings.Split(emailAddresses, ",")
	}

	subject := &cmapi.X509Subject{}
	if organizations, found := ingLikeAnnotations[cmapi.SubjectOrganizationsAnnotationKey]; found {
		organizations, err := util.SplitWithEscapeCSV(organizations)
		subject.Organizations = organizations

		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.SubjectOrganizationsAnnotationKey, err)
		}
	}

	if organizationalUnits, found := ingLikeAnnotations[cmapi.SubjectOrganizationalUnitsAnnotationKey]; found {
		organizationalUnits, err := util.SplitWithEscapeCSV(organizationalUnits)
		subject.OrganizationalUnits = organizationalUnits

		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.SubjectOrganizationsAnnotationKey, err)
		}
	}

	if countries, found := ingLikeAnnotations[cmapi.SubjectCountriesAnnotationKey]; found {
		countries, err := util.SplitWithEscapeCSV(countries)
		subject.Countries = countries

		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.SubjectCountriesAnnotationKey, err)
		}
	}

	if provinces, found := ingLikeAnnotations[cmapi.SubjectProvincesAnnotationKey]; found {
		provinces, err := util.SplitWithEscapeCSV(provinces)
		subject.Provinces = provinces

		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.SubjectProvincesAnnotationKey, err)
		}
	}

	if localities, found := ingLikeAnnotations[cmapi.SubjectLocalitiesAnnotationKey]; found {
		localities, err := util.SplitWithEscapeCSV(localities)
		subject.Localities = localities

		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.SubjectLocalitiesAnnotationKey, err)
		}
	}

	if postalCodes, found := ingLikeAnnotations[cmapi.SubjectPostalCodesAnnotationKey]; found {
		postalCodes, err := util.SplitWithEscapeCSV(postalCodes)
		subject.PostalCodes = postalCodes

		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.SubjectPostalCodesAnnotationKey, err)
		}
	}

	if streetAddresses, found := ingLikeAnnotations[cmapi.SubjectStreetAddressesAnnotationKey]; found {
		streetAddresses, err := util.SplitWithEscapeCSV(streetAddresses)
		subject.StreetAddresses = streetAddresses

		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.SubjectStreetAddressesAnnotationKey, err)
		}
	}

	if serialNumber, found := ingLikeAnnotations[cmapi.SubjectSerialNumberAnnotationKey]; found {
		subject.SerialNumber = serialNumber
	}

	emptySubject := &cmapi.X509Subject{}
	if !reflect.DeepEqual(emptySubject, subject) {
		crt.Spec.Subject = subject
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

	if revisionHistoryLimit, found := ingLikeAnnotations[cmapi.RevisionHistoryLimitAnnotationKey]; found {
		limit, err := strconv.ParseInt(revisionHistoryLimit, 10, 32)
		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.RevisionHistoryLimitAnnotationKey, err)
		}

		if limit < 1 {
			return fmt.Errorf("%w %q: revision history limit must be a positive number %q", errInvalidIngressAnnotation, cmapi.RevisionHistoryLimitAnnotationKey, revisionHistoryLimit)
		}

		crt.Spec.RevisionHistoryLimit = ptr.To(int32(limit))
	}

	if privateKeyAlgorithm, found := ingLikeAnnotations[cmapi.PrivateKeyAlgorithmAnnotationKey]; found {
		algorithm := cmapi.PrivateKeyAlgorithm(privateKeyAlgorithm)
		switch algorithm {
		case cmapi.RSAKeyAlgorithm,
			cmapi.ECDSAKeyAlgorithm,
			cmapi.Ed25519KeyAlgorithm:
			// ok
		default:
			return fmt.Errorf("%w %q: invalid private key algorithm %q", errInvalidIngressAnnotation, cmapi.PrivateKeyAlgorithmAnnotationKey, privateKeyAlgorithm)
		}

		if crt.Spec.PrivateKey == nil {
			crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{Algorithm: algorithm}
		} else {
			crt.Spec.PrivateKey.Algorithm = algorithm
		}
	}

	if privateKeyEncoding, found := ingLikeAnnotations[cmapi.PrivateKeyEncodingAnnotationKey]; found {
		encoding := cmapi.PrivateKeyEncoding(privateKeyEncoding)
		if encoding != cmapi.PKCS1 &&
			encoding != cmapi.PKCS8 {
			return fmt.Errorf("%w %q: invalid private key encoding %q", errInvalidIngressAnnotation, cmapi.PrivateKeyEncodingAnnotationKey, privateKeyEncoding)
		}

		if crt.Spec.PrivateKey == nil {
			crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{Encoding: encoding}
		} else {
			crt.Spec.PrivateKey.Encoding = encoding
		}
	}

	if privateKeySize, found := ingLikeAnnotations[cmapi.PrivateKeySizeAnnotationKey]; found {
		size, err := strconv.Atoi(privateKeySize)
		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.PrivateKeySizeAnnotationKey, err)
		}

		// default algorithm
		algorithm := cmapi.RSAKeyAlgorithm
		if crt.Spec.PrivateKey != nil && crt.Spec.PrivateKey.Algorithm != "" {
			algorithm = crt.Spec.PrivateKey.Algorithm
		}

		switch algorithm {
		case cmapi.RSAKeyAlgorithm:
			if size < 2048 || size > 8192 {
				return fmt.Errorf("%w %q: invalid private key size for RSA algorithm %q", errInvalidIngressAnnotation, cmapi.PrivateKeySizeAnnotationKey, privateKeySize)
			}
		case cmapi.ECDSAKeyAlgorithm:
			switch size {
			case 256, 384, 521:
				// ok
			default:
				return fmt.Errorf("%w %q: invalid private key size for ECDSA algorithm %q", errInvalidIngressAnnotation, cmapi.PrivateKeySizeAnnotationKey, privateKeySize)
			}
		}

		if crt.Spec.PrivateKey == nil {
			crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{Size: size}
		} else {
			crt.Spec.PrivateKey.Size = size
		}
	}

	if privateKeyRotationPolicy, found := ingLikeAnnotations[cmapi.PrivateKeyRotationPolicyAnnotationKey]; found {
		rotationPolicy := cmapi.PrivateKeyRotationPolicy(privateKeyRotationPolicy)
		if rotationPolicy != cmapi.RotationPolicyNever &&
			rotationPolicy != cmapi.RotationPolicyAlways {
			return fmt.Errorf("%w %q: invalid private key rotation policy %q", errInvalidIngressAnnotation, cmapi.PrivateKeyRotationPolicyAnnotationKey, privateKeyRotationPolicy)
		}

		if crt.Spec.PrivateKey == nil {
			crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{RotationPolicy: rotationPolicy}
		} else {
			crt.Spec.PrivateKey.RotationPolicy = rotationPolicy
		}
	}

	if secretTemplateJson, found := ingLikeAnnotations[cmapi.IngressSecretTemplate]; found {
		decoder := json.NewDecoder(strings.NewReader(secretTemplateJson))
		decoder.DisallowUnknownFields()

		var secretTemplate = new(cmapi.CertificateSecretTemplate)
		if err := decoder.Decode(secretTemplate); err != nil {
			return fmt.Errorf("%w %q: error parsing secret template JSON: %v", errInvalidIngressAnnotation, cmapi.IngressSecretTemplate, err)
		}
		for annotationKey := range secretTemplate.Annotations {
			if strings.HasPrefix(annotationKey, "cert-manager.io/") {
				return fmt.Errorf("%w %q: secretTemplate must not have cert-manager.io/ annotations: %q", errInvalidIngressAnnotation, cmapi.IngressSecretTemplate, annotationKey)
			}
		}
		if len(secretTemplate.Annotations) > 0 || len(secretTemplate.Labels) > 0 {
			crt.Spec.SecretTemplate = secretTemplate
		}
	}

	return nil
}
