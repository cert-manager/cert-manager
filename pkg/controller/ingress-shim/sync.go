/*
Copyright 2019 The Jetstack cert-manager contributors.

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
	"context"
	"fmt"
	"reflect"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/util"
)

const (
	// editInPlaceAnnotation is used to toggle the use of ingressClass instead
	// of ingress on the created Certificate resource
	editInPlaceAnnotation = "certmanager.k8s.io/acme-http01-edit-in-place"
	// issuerNameAnnotation can be used to override the issuer specified on the
	// created Certificate resource.
	issuerNameAnnotation = "certmanager.k8s.io/issuer"
	// clusterIssuerNameAnnotation can be used to override the issuer specified on the
	// created Certificate resource. The Certificate will reference the
	// specified *ClusterIssuer* instead of normal issuer.
	clusterIssuerNameAnnotation = "certmanager.k8s.io/cluster-issuer"
	// acmeIssuerChallengeTypeAnnotation can be used to override the default ACME challenge
	// type to be used when the specified issuer is an ACME issuer
	acmeIssuerChallengeTypeAnnotation = "certmanager.k8s.io/acme-challenge-type"
	// acmeIssuerDNS01ProviderNameAnnotation can be used to override the default dns01 provider
	// configured on the issuer if the challenge type is set to dns01
	acmeIssuerDNS01ProviderNameAnnotation = "certmanager.k8s.io/acme-dns01-provider"
	// acmeIssuerHTTP01IngressClassAnnotation can be used to override the http01 ingressClass
	// if the challenge type is set to http01
	acmeIssuerHTTP01IngressClassAnnotation = "certmanager.k8s.io/acme-http01-ingress-class"

	ingressClassAnnotation = util.IngressKey
)

var ingressGVK = extv1beta1.SchemeGroupVersion.WithKind("Ingress")

func (c *Controller) Sync(ctx context.Context, ing *extv1beta1.Ingress) error {
	if !shouldSync(ing, c.defaults.autoCertificateAnnotations) {
		klog.Infof("Not syncing ingress %s/%s as it does not contain necessary annotations", ing.Namespace, ing.Name)
		return nil
	}

	issuerName, issuerKind := c.issuerForIngress(ing)
	if issuerName == "" {
		c.Recorder.Eventf(ing, corev1.EventTypeWarning, "BadConfig", "Issuer name annotation is not set and a default issuer has not been configured")
		return nil
	}

	issuer, err := c.helper.GetGenericIssuer(v1alpha1.ObjectReference{
		Name: issuerName,
		Kind: issuerKind,
	}, ing.Namespace)
	if apierrors.IsNotFound(err) {
		c.Recorder.Eventf(ing, corev1.EventTypeWarning, "BadConfig", "%s resource %q not found", issuerKind, issuerName)
		return nil
	}
	if err != nil {
		return err
	}

	errs := c.validateIngress(ing)
	if len(errs) > 0 {
		errMsg := errs[0].Error()
		if len(errs) > 1 {
			errMsg = utilerrors.NewAggregate(errs).Error()
		}
		c.Recorder.Eventf(ing, corev1.EventTypeWarning, "BadConfig", errMsg)
		return nil
	}

	newCrts, updateCrts, err := c.buildCertificates(ing, issuer, issuerKind)
	if err != nil {
		return err
	}

	for _, crt := range newCrts {
		_, err := c.CMClient.CertmanagerV1alpha1().Certificates(crt.Namespace).Create(crt)
		if err != nil {
			return err
		}
		c.Recorder.Eventf(ing, corev1.EventTypeNormal, "CreateCertificate", "Successfully created Certificate %q", crt.Name)
	}

	for _, crt := range updateCrts {
		_, err := c.CMClient.CertmanagerV1alpha1().Certificates(crt.Namespace).Update(crt)
		if err != nil {
			return err
		}
		c.Recorder.Eventf(ing, corev1.EventTypeNormal, "UpdateCertificate", "Successfully updated Certificate %q", crt.Name)
	}

	return nil
}

func (c *Controller) validateIngress(ing *extv1beta1.Ingress) []error {
	var errs []error
	if ing.Annotations != nil {
		challengeType := ing.Annotations[acmeIssuerChallengeTypeAnnotation]
		switch challengeType {
		case "", "http01":
		case "dns01":
			providerName := ing.Annotations[acmeIssuerDNS01ProviderNameAnnotation]
			if providerName == "" {
				errs = append(errs, fmt.Errorf("No acme dns01 challenge provider specified"))
			}
		default:
			errs = append(errs, fmt.Errorf("Invalid acme challenge type specified %q", challengeType))
		}
	}
	for i, tls := range ing.Spec.TLS {
		// validate the ingress TLS block
		if len(tls.Hosts) == 0 {
			errs = append(errs, fmt.Errorf("Secret %q for ingress TLS has no hosts specified", tls.SecretName))
		}
		if tls.SecretName == "" {
			errs = append(errs, fmt.Errorf("TLS entry %d for hosts %v must specify a secretName", i, tls.Hosts))
		}
	}
	return errs
}

func (c *Controller) buildCertificates(ing *extv1beta1.Ingress, issuer v1alpha1.GenericIssuer, issuerKind string) (new, update []*v1alpha1.Certificate, _ error) {
	var newCrts []*v1alpha1.Certificate
	var updateCrts []*v1alpha1.Certificate
	for _, tls := range ing.Spec.TLS {
		existingCrt, err := c.certificateLister.Certificates(ing.Namespace).Get(tls.SecretName)
		if !apierrors.IsNotFound(err) && err != nil {
			return nil, nil, err
		}

		crt := &v1alpha1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:            tls.SecretName,
				Namespace:       ing.Namespace,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ing, ingressGVK)},
			},
			Spec: v1alpha1.CertificateSpec{
				DNSNames:   tls.Hosts,
				SecretName: tls.SecretName,
				IssuerRef: v1alpha1.ObjectReference{
					Name: issuer.GetObjectMeta().Name,
					Kind: issuerKind,
				},
			},
		}

		err = c.setIssuerSpecificConfig(crt, issuer, ing, tls)
		if err != nil {
			return nil, nil, err
		}

		// check if a Certificate for this TLS entry already exists, and if it
		// does then skip this entry
		if existingCrt != nil {
			klog.Infof("Certificate %q for ingress %q already exists", tls.SecretName, ing.Name)

			if !certNeedsUpdate(existingCrt, crt) {
				klog.Infof("Certificate %q for ingress %q is up to date", tls.SecretName, ing.Name)
				continue
			}

			updateCrt := existingCrt.DeepCopy()

			updateCrt.Spec.DNSNames = tls.Hosts
			updateCrt.Spec.SecretName = tls.SecretName
			updateCrt.Spec.IssuerRef.Name = issuer.GetObjectMeta().Name
			updateCrt.Spec.IssuerRef.Kind = issuerKind
			err = c.setIssuerSpecificConfig(updateCrt, issuer, ing, tls)
			if err != nil {
				return nil, nil, err
			}
			updateCrts = append(updateCrts, updateCrt)
		} else {
			newCrts = append(newCrts, crt)
		}
	}
	return newCrts, updateCrts, nil
}

// certNeedsUpdate checks and returns true if two Certificates are equal
func certNeedsUpdate(a, b *v1alpha1.Certificate) bool {
	if a.Name != b.Name {
		return true
	}

	if len(a.Spec.DNSNames) != len(b.Spec.DNSNames) {
		return true
	}

	for i := range a.Spec.DNSNames {
		if a.Spec.DNSNames[i] != b.Spec.DNSNames[i] {
			return true
		}
	}

	if a.Spec.SecretName != b.Spec.SecretName {
		return true
	}

	if a.Spec.IssuerRef.Name != b.Spec.IssuerRef.Name {
		return true
	}

	if a.Spec.IssuerRef.Kind != b.Spec.IssuerRef.Kind {
		return true
	}

	var configA, configB []v1alpha1.DomainSolverConfig

	if a.Spec.ACME != nil {
		configA = a.Spec.ACME.Config
	}

	if b.Spec.ACME != nil {
		configB = b.Spec.ACME.Config
	}

	if !reflect.DeepEqual(configA, configB) {
		return true
	}

	return false
}

func (c *Controller) setIssuerSpecificConfig(crt *v1alpha1.Certificate, issuer v1alpha1.GenericIssuer, ing *extv1beta1.Ingress, tls extv1beta1.IngressTLS) error {
	ingAnnotations := ing.Annotations
	if ingAnnotations == nil {
		ingAnnotations = map[string]string{}
	}
	// for ACME issuers
	if issuer.GetSpec().ACME != nil {
		challengeType, ok := ingAnnotations[acmeIssuerChallengeTypeAnnotation]
		if !ok {
			challengeType = c.defaults.acmeIssuerChallengeType
		}
		domainCfg := v1alpha1.DomainSolverConfig{
			Domains: tls.Hosts,
		}
		switch challengeType {
		case "http01":
			domainCfg.HTTP01 = &v1alpha1.HTTP01SolverConfig{}
			editInPlace, ok := ingAnnotations[editInPlaceAnnotation]
			// If annotation isn't present, or it's set to true, edit the existing ingress
			if ok && editInPlace == "true" {
				domainCfg.HTTP01.Ingress = ing.Name
			} else {
				ingressClass, ok := ingAnnotations[acmeIssuerHTTP01IngressClassAnnotation]
				if ok {
					domainCfg.HTTP01.IngressClass = &ingressClass
				} else {
					ingressClass, ok := ingAnnotations[ingressClassAnnotation]
					if ok {
						domainCfg.HTTP01.IngressClass = &ingressClass
					}
				}
			}
		case "dns01":
			dnsProvider, ok := ingAnnotations[acmeIssuerDNS01ProviderNameAnnotation]
			if !ok {
				dnsProvider = c.defaults.acmeIssuerDNS01ProviderName
			}
			if dnsProvider == "" {
				return fmt.Errorf("no acme issuer dns01 challenge provider specified")
			}
			domainCfg.DNS01 = &v1alpha1.DNS01SolverConfig{Provider: dnsProvider}
		default:
			return fmt.Errorf("invalid acme issuer challenge type specified %q", challengeType)
		}
		crt.Spec.ACME = &v1alpha1.ACMECertificateConfig{Config: []v1alpha1.DomainSolverConfig{domainCfg}}
	}
	return nil
}

// shouldSync returns true if this ingress should have a Certificate resource
// created for it
func shouldSync(ing *extv1beta1.Ingress, autoCertificateAnnotations []string) bool {
	annotations := ing.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}
	if _, ok := annotations[issuerNameAnnotation]; ok {
		return true
	}
	if _, ok := annotations[clusterIssuerNameAnnotation]; ok {
		return true
	}
	for _, x := range autoCertificateAnnotations {
		if s, ok := annotations[x]; ok {
			if b, _ := strconv.ParseBool(s); b {
				return true
			}
		}
	}
	if _, ok := annotations[acmeIssuerChallengeTypeAnnotation]; ok {
		return true
	}
	if _, ok := annotations[acmeIssuerDNS01ProviderNameAnnotation]; ok {
		return true
	}
	return false
}

// issuerForIngress will determine the issuer that should be specified on a
// Certificate created for the given Ingress resource. If one is not set, the
// default issuer given to the controller will be used.
func (c *Controller) issuerForIngress(ing *extv1beta1.Ingress) (name string, kind string) {
	name = c.defaults.issuerName
	kind = c.defaults.issuerKind
	annotations := ing.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}
	if issuerName, ok := annotations[issuerNameAnnotation]; ok {
		name = issuerName
		kind = v1alpha1.IssuerKind
	}
	if issuerName, ok := annotations[clusterIssuerNameAnnotation]; ok {
		name = issuerName
		kind = v1alpha1.ClusterIssuerKind
	}
	return name, kind
}
