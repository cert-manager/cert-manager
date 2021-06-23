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
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	gatewayapi "sigs.k8s.io/gateway-api/apis/v1alpha1"

	cmacme "github.com/jetstack/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	reasonBadConfig         = "BadConfig"
	reasonCreateCertificate = "CreateCertificate"
	reasonUpdateCertificate = "UpdateCertificate"
	reasonDeleteCertificate = "DeleteCertificate"
)

var ingressGVK = networkingv1beta1.SchemeGroupVersion.WithKind("Ingress")
var gatewayGVK = gatewayapi.SchemeGroupVersion.WithKind("Gateway")

func (c *controller) Sync(ctx context.Context, obj runtime.Object) error {
	ob, ok := obj.(metav1.Object)
	if !ok {
		return fmt.Errorf("sync: Expected metav1.Object, got %T", obj)
	}

	log := logf.WithResource(logf.FromContext(ctx), ob)
	ctx = logf.NewContext(ctx, log)

	if !shouldSync(ob, c.defaults.autoCertificateAnnotations) {
		logf.V(logf.DebugLevel).Infof("not syncing %T as it does not contain a %q or %q annotation",
			obj, ob.GetNamespace(), ob.GetName(),
			cmapi.IngressIssuerNameAnnotationKey, cmapi.IngressClusterIssuerNameAnnotationKey)
		return nil
	}

	issuerName, issuerKind, issuerGroup, err := c.issuerForObject(ob)
	if err != nil {
		log.Error(err, "failed to determine issuer to be used for resource")
		c.recorder.Eventf(obj, corev1.EventTypeWarning, reasonBadConfig, "Could not determine issuer for %T due to bad annotations: %s",
			obj,
			err,
		)
		return nil
	}

	errs := c.validateObject(ob)
	if len(errs) > 0 {
		errMsg := errs[0].Error()
		if len(errs) > 1 {
			errMsg = utilerrors.NewAggregate(errs).Error()
		}
		c.recorder.Eventf(obj, corev1.EventTypeWarning, reasonBadConfig, errMsg)
		return nil
	}

	newCrts, updateCrts, err := c.buildCertificates(ctx, ob, issuerName, issuerKind, issuerGroup)
	if err != nil {
		return err
	}

	for _, crt := range newCrts {
		_, err := c.cmClient.CertmanagerV1().Certificates(crt.Namespace).Create(ctx, crt, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		c.recorder.Eventf(obj, corev1.EventTypeNormal, reasonCreateCertificate, "Successfully created Certificate %q", crt.Name)
	}

	for _, crt := range updateCrts {
		_, err := c.cmClient.CertmanagerV1().Certificates(crt.Namespace).Update(ctx, crt, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		c.recorder.Eventf(obj, corev1.EventTypeNormal, reasonUpdateCertificate, "Successfully updated Certificate %q", crt.Name)
	}

	unrequiredCrts, err := c.findUnrequiredCertificates(ob)
	if err != nil {
		return err
	}

	for _, crt := range unrequiredCrts {
		err = c.cmClient.CertmanagerV1().Certificates(crt.Namespace).Delete(ctx, crt.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
		c.recorder.Eventf(obj, corev1.EventTypeNormal, reasonDeleteCertificate, "Successfully deleted unrequired Certificate %q", crt.Name)
	}

	return nil
}

func (c *controller) validateObject(obj metav1.Object) []error {
	switch o := obj.(type) {
	case *networkingv1beta1.Ingress:
		// check for duplicate values of networkingv1beta1.IngressTLS.SecretName
		var errs []error
		namedSecrets := make(map[string]int)
		for _, tls := range o.Spec.TLS {
			namedSecrets[tls.SecretName]++
		}
		// not doing this in the previous for-loop to avoid erroring more than once for the same SecretName
		for name, n := range namedSecrets {
			if n > 1 {
				errs = append(errs, fmt.Errorf("duplicate TLS entry for secretName %q", name))
			}
		}
		return errs
	case *gatewayapi.Gateway:
		return validateGatewayListeners(o.Spec.Listeners)
	default:
		return []error{fmt.Errorf("validateObject: can't handle object %T, expected ingress or gateway", obj)}
	}
}

func validateIngressTLSBlock(tlsBlock networkingv1beta1.IngressTLS) []error {
	// unlikely that _both_ SecretName and Hosts would be empty, but still returning []error for consistency
	var errs []error

	if len(tlsBlock.Hosts) == 0 {
		errs = append(errs, fmt.Errorf("secret %q for ingress TLS has no hosts specified", tlsBlock.SecretName))
	}
	if tlsBlock.SecretName == "" {
		errs = append(errs, fmt.Errorf("TLS entry for hosts %v must specify a secretName", tlsBlock.Hosts))
	}
	return errs
}

func validateGatewayListeners(listeners []gatewayapi.Listener) []error {
	var errs []error

	for _, l := range listeners {
		if l.TLS == nil {
			return []error{fmt.Errorf("listener for host %s does not specify a TLS block", *l.Hostname)}
		}
		if l.TLS.CertificateRef.Group != "core" {
			errs = append(
				errs,
				fmt.Errorf(
					"unsupported certificateRef.group, want %s got %s",
					"core",
					l.TLS.CertificateRef.Group,
				),
			)
		}
		if *l.TLS.Mode == gatewayapi.TLSModePassthrough {
			errs = append(
				errs,
				fmt.Errorf(
					"listener for %s has mode %s, the only valid mode is %s",
					*l.Hostname,
					gatewayapi.TLSModePassthrough,
					gatewayapi.TLSModeTerminate,
				),
			)
		}
	}
	return errs
}

func (c *controller) buildCertificates(ctx context.Context, obj metav1.Object,
	issuerName, issuerKind, issuerGroup string) (new, update []*cmapi.Certificate, _ error) {
	log := logf.FromContext(ctx)

	var newCrts []*cmapi.Certificate
	var updateCrts []*cmapi.Certificate

	type certificateShimInfo struct {
		// tlsHosts key = secret ref, value = dns host names
		tlsHosts map[corev1.ObjectReference][]string
		gvk      schema.GroupVersionKind
	}

	certs := certificateShimInfo{
		tlsHosts: map[corev1.ObjectReference][]string{},
	}

	switch o := obj.(type) {
	case *networkingv1beta1.Ingress:
		certs.gvk = ingressGVK
		for i, tls := range o.Spec.TLS {
			errs := validateIngressTLSBlock(tls)
			// if this tls entry is invalid, record an error event on IngressOrGateway object and continue to the next tls entry
			if len(errs) > 0 {
				errMsg := utilerrors.NewAggregate(errs).Error()
				c.recorder.Eventf(o, corev1.EventTypeWarning, reasonBadConfig, fmt.Sprintf("TLS entry %d is invalid: %s", i, errMsg))
				continue
			}
			certs.tlsHosts[corev1.ObjectReference{
				Namespace: o.Namespace,
				Name:      tls.SecretName,
			}] = tls.Hosts
		}
	case *gatewayapi.Gateway:
		certs.gvk = gatewayGVK
		errs := validateGatewayListeners(o.Spec.Listeners)
		if len(errs) > 0 {
			c.recorder.Eventf(o, corev1.EventTypeWarning, reasonBadConfig, fmt.Sprintf("%s", utilerrors.NewAggregate(errs)))
			return nil, nil, utilerrors.NewAggregate(errs)
		}
		for _, l := range o.Spec.Listeners {
			secretRef := corev1.ObjectReference{
				Namespace: o.Namespace,
				Name:      l.TLS.CertificateRef.Name,
			}
			certs.tlsHosts[secretRef] = append(certs.tlsHosts[secretRef], fmt.Sprintf("%s", *l.Hostname))
		}
	default:
		return nil, nil, fmt.Errorf("buildCertificates: expected ingress or gateway, got %T", obj)
	}

	for secretRef, hosts := range certs.tlsHosts {
		existingCrt, err := c.certificateLister.Certificates(secretRef.Namespace).Get(secretRef.Name)
		if !apierrors.IsNotFound(err) && err != nil {
			return nil, nil, err
		}

		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:            secretRef.Name,
				Namespace:       secretRef.Namespace,
				Labels:          obj.GetLabels(),
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(obj, certs.gvk)},
			},
			Spec: cmapi.CertificateSpec{
				DNSNames:   hosts,
				SecretName: secretRef.Name,
				IssuerRef: cmmeta.ObjectReference{
					Name:  issuerName,
					Kind:  issuerKind,
					Group: issuerGroup,
				},
				Usages: cmapi.DefaultKeyUsages(),
			},
		}

		if certs.gvk == ingressGVK {
			setIssuerSpecificConfig(crt, obj.(*networkingv1beta1.Ingress))
		}
		if err := translateIngressAnnotations(crt, obj.GetAnnotations()); err != nil {
			return nil, nil, err
		}

		// check if a Certificate for this TLS entry already exists, and if it
		// does then skip this entry
		if existingCrt != nil {
			log := logf.WithRelatedResource(log, existingCrt)
			log.V(logf.DebugLevel).Info("certificate already exists for this object, ensuring it is up to date")

			if metav1.GetControllerOf(existingCrt) == nil {
				log.V(logf.InfoLevel).Info("certificate resource has no owner. refusing to update non-owned certificate resource for object")
				continue
			}

			if !metav1.IsControlledBy(existingCrt, obj) {
				log.V(logf.InfoLevel).Info("certificate resource is not owned by this object. refusing to update non-owned certificate resource for object")
				continue
			}

			if !certNeedsUpdate(existingCrt, crt) {
				log.V(logf.DebugLevel).Info("certificate resource is already up to date for object")
				continue
			}

			updateCrt := existingCrt.DeepCopy()

			updateCrt.Spec = crt.Spec
			updateCrt.Labels = crt.Labels
			if certs.gvk == ingressGVK {
				setIssuerSpecificConfig(updateCrt, obj.(*networkingv1beta1.Ingress))
			}
			updateCrts = append(updateCrts, updateCrt)
		} else {
			newCrts = append(newCrts, crt)
		}
	}
	return newCrts, updateCrts, nil
}

func (c *controller) findUnrequiredCertificates(obj metav1.Object) ([]*cmapi.Certificate, error) {
	var unrequired []*cmapi.Certificate
	// TODO: investigate selector which filters for certificates controlled by the ingress
	crts, err := c.certificateLister.Certificates(obj.GetNamespace()).List(labels.Everything())
	if err != nil {
		return nil, err
	}

	for _, crt := range crts {
		if isUnrequiredCertificate(crt, obj) {
			unrequired = append(unrequired, crt)
		}
	}

	return unrequired, nil
}

func isUnrequiredCertificate(crt *cmapi.Certificate, obj metav1.Object) bool {
	if !metav1.IsControlledBy(crt, obj) {
		return false
	}

	switch o := obj.(type) {
	case *networkingv1beta1.Ingress:
		for _, tls := range o.Spec.TLS {
			if crt.Spec.SecretName == tls.SecretName {
				return false
			}
		}
	case *gatewayapi.Gateway:
		for _, l := range o.Spec.Listeners {
			if crt.Spec.SecretName == l.TLS.CertificateRef.Name {
				return false
			}
		}
	}
	return true
}

// certNeedsUpdate checks and returns true if two Certificates differ
func certNeedsUpdate(a, b *cmapi.Certificate) bool {
	if a.Name != b.Name {
		return true
	}

	// TODO: we may need to allow users to edit the managed Certificate resources
	// to add their own labels directly.
	// Right now, we'll reset/remove the label values back automatically.
	// Let's hope no other controllers do this automatically, else we'll start fighting...
	if !reflect.DeepEqual(a.Labels, b.Labels) {
		return true
	}

	if a.Spec.CommonName != b.Spec.CommonName {
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

	return false
}

func setIssuerSpecificConfig(crt *cmapi.Certificate, ing *networkingv1beta1.Ingress) {
	ingAnnotations := ing.Annotations
	if ingAnnotations == nil {
		ingAnnotations = map[string]string{}
	}

	// for ACME issuers
	editInPlaceVal := ingAnnotations[cmacme.IngressEditInPlaceAnnotationKey]
	editInPlace := editInPlaceVal == "true"
	if editInPlace {
		if crt.Annotations == nil {
			crt.Annotations = make(map[string]string)
		}
		crt.Annotations[cmacme.ACMECertificateHTTP01IngressNameOverride] = ing.Name
		// set IssueTemporaryCertificateAnnotation to true in order to behave
		// better when ingress-gce is being used.
		crt.Annotations[cmapi.IssueTemporaryCertificateAnnotation] = "true"
	}

	ingressClassVal, hasIngressClassVal := ingAnnotations[cmapi.IngressACMEIssuerHTTP01IngressClassAnnotationKey]
	if hasIngressClassVal {
		if crt.Annotations == nil {
			crt.Annotations = make(map[string]string)
		}
		crt.Annotations[cmacme.ACMECertificateHTTP01IngressClassOverride] = ingressClassVal
	}
}

// shouldSync returns true if this object should have a Certificate resource
// created for it
func shouldSync(obj metav1.Object, autoCertificateAnnotations []string) bool {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	if _, ok := annotations[cmapi.IngressIssuerNameAnnotationKey]; ok {
		return true
	}
	if _, ok := annotations[cmapi.IngressClusterIssuerNameAnnotationKey]; ok {
		return true
	}
	for _, x := range autoCertificateAnnotations {
		if s, ok := annotations[x]; ok {
			if b, _ := strconv.ParseBool(s); b {
				return true
			}
		}
	}
	return false
}

// issuerForObject will determine the issuer that should be specified on a
// Certificate created for the given resource. If one is not set, the
// default issuer given to the controller will be used.
func (c *controller) issuerForObject(obj metav1.Object) (name, kind, group string, err error) {
	var errs []string

	name = c.defaults.issuerName
	kind = c.defaults.issuerKind
	group = c.defaults.issuerGroup
	annotations := obj.GetAnnotations()

	if annotations == nil {
		annotations = map[string]string{}
	}

	issuerName, issuerNameOK := annotations[cmapi.IngressIssuerNameAnnotationKey]
	if issuerNameOK {
		name = issuerName
		kind = cmapi.IssuerKind
	}

	clusterIssuerName, clusterIssuerNameOK := annotations[cmapi.IngressClusterIssuerNameAnnotationKey]
	if clusterIssuerNameOK {
		name = clusterIssuerName
		kind = cmapi.ClusterIssuerKind
	}

	kindName, kindNameOK := annotations[cmapi.IssuerKindAnnotationKey]
	if kindNameOK {
		kind = kindName
	}

	groupName, groupNameOK := annotations[cmapi.IssuerGroupAnnotationKey]
	if groupNameOK {
		group = groupName
	}

	if len(name) == 0 {
		errs = append(errs, "failed to determine issuer name to be used for ingress resource")
	}

	if issuerNameOK && clusterIssuerNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set",
				cmapi.IngressIssuerNameAnnotationKey, cmapi.IngressClusterIssuerNameAnnotationKey))
	}

	if clusterIssuerNameOK && groupNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set",
				cmapi.IngressClusterIssuerNameAnnotationKey, cmapi.IssuerGroupAnnotationKey))
	}

	if clusterIssuerNameOK && kindNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set",
				cmapi.IngressClusterIssuerNameAnnotationKey, cmapi.IssuerKindAnnotationKey))
	}

	if len(errs) > 0 {
		return "", "", "", errors.New(strings.Join(errs, ", "))
	}

	return name, kind, group, nil
}
