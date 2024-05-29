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
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"

	internalcertificates "github.com/cert-manager/cert-manager/internal/controller/certificates"
	"github.com/cert-manager/cert-manager/internal/controller/feature"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/cert-manager/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	utilfeature "github.com/cert-manager/cert-manager/pkg/util/feature"
)

const (
	reasonBadConfig         = "BadConfig"
	reasonCreateCertificate = "CreateCertificate"
	reasonUpdateCertificate = "UpdateCertificate"
	reasonDeleteCertificate = "DeleteCertificate"
)

var ingressV1GVK = networkingv1.SchemeGroupVersion.WithKind("Ingress")
var gatewayGVK = gwapi.SchemeGroupVersion.WithKind("Gateway")

// SyncFn is the reconciliation function passed to a certificate-shim's
// controller.
type SyncFn func(context.Context, metav1.Object) error

// SyncFnFor contains logic to reconcile any "Ingress-like" object.
//
// An "Ingress-like" object is a resource such as an Ingress, a Gateway or an
// HTTPRoute. Due to their similarity, the reconciliation function for them is
// common. Reconciling an Ingress-like object means looking at its annotations
// and creating a Certificate with matching DNS names and secretNames from the
// TLS configuration of the Ingress-like object.
func SyncFnFor(
	rec record.EventRecorder,
	log logr.Logger,
	cmClient clientset.Interface,
	cmLister cmlisters.CertificateLister,
	defaults controller.IngressShimOptions,
	fieldManager string,
) SyncFn {
	return func(ctx context.Context, ingLike metav1.Object) error {
		log := logf.WithResource(log, ingLike)
		ctx = logf.NewContext(ctx, log)

		// rec.Eventf requires a runtime.Object, not a metav1.Object.
		ingLikeObj, ok := ingLike.(runtime.Object)
		if !ok {
			return fmt.Errorf("programmer mistake: %T was expected to be a runtime.Object", ingLike)
		}

		// The flag --auto-certificate-annotations as well as the default
		// "kubernetes.io/tls-acme" annotation are only enabled for the Ingress
		// resource.
		var autoAnnotations []string
		if _, ok := ingLike.(*networkingv1.Ingress); ok {
			autoAnnotations = defaults.DefaultAutoCertificateAnnotations
		}

		if !hasShimAnnotation(ingLike, autoAnnotations) {
			logf.V(logf.DebugLevel).Infof("not syncing ingress resource as it does not contain a %q or %q annotation",
				cmapi.IngressIssuerNameAnnotationKey, cmapi.IngressClusterIssuerNameAnnotationKey)
			return nil
		}

		if isDeletedInForeground(ingLike) {
			logf.V(logf.DebugLevel).Infof("not syncing ingress resource as it is being deleted via foreground cascading")
			return nil
		}

		issuerName, issuerKind, issuerGroup, err := issuerForIngressLike(defaults, ingLike)
		if err != nil {
			log.Error(err, "failed to determine issuer to be used for ingress resource")
			rec.Eventf(ingLikeObj, corev1.EventTypeWarning, reasonBadConfig, "Could not determine issuer for ingress due to bad annotations: %s",
				err)
			return nil
		}

		err = validateIngressLike(ingLike).ToAggregate()
		if err != nil {
			rec.Eventf(ingLikeObj, corev1.EventTypeWarning, reasonBadConfig, err.Error())
			return nil
		}

		newCrts, updateCrts, err := buildCertificates(rec, log, cmLister, ingLike, issuerName, issuerKind, issuerGroup)
		if err != nil {
			return err
		}

		for _, crt := range newCrts {
			_, err := cmClient.CertmanagerV1().Certificates(crt.Namespace).Create(ctx, crt, metav1.CreateOptions{FieldManager: fieldManager})
			if err != nil {
				return err
			}
			rec.Eventf(ingLikeObj, corev1.EventTypeNormal, reasonCreateCertificate, "Successfully created Certificate %q", crt.Name)
		}

		for _, crt := range updateCrts {

			if utilfeature.DefaultFeatureGate.Enabled(feature.ServerSideApply) {
				err = internalcertificates.Apply(ctx, cmClient, fieldManager, &cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:            crt.Name,
						Namespace:       crt.Namespace,
						Labels:          crt.Labels,
						OwnerReferences: crt.OwnerReferences,
					},
					Spec: cmapi.CertificateSpec{
						DNSNames:    crt.Spec.DNSNames,
						IPAddresses: crt.Spec.IPAddresses,
						SecretName:  crt.Spec.SecretName,
						IssuerRef:   crt.Spec.IssuerRef,
						Usages:      crt.Spec.Usages,
					},
				})
			} else {
				_, err = cmClient.CertmanagerV1().Certificates(crt.Namespace).Update(ctx, crt, metav1.UpdateOptions{})
			}
			if err != nil {
				return err
			}

			rec.Eventf(ingLikeObj, corev1.EventTypeNormal, reasonUpdateCertificate, "Successfully updated Certificate %q", crt.Name)
		}

		certs, err := cmLister.Certificates(ingLike.GetNamespace()).List(labels.Everything())
		if err != nil {
			return err
		}
		unrequiredCertNames := findCertificatesToBeRemoved(certs, ingLike)

		for _, certName := range unrequiredCertNames {
			err = cmClient.CertmanagerV1().Certificates(ingLike.GetNamespace()).Delete(ctx, certName, metav1.DeleteOptions{})
			if err != nil {
				return err
			}
			rec.Eventf(ingLikeObj, corev1.EventTypeNormal, reasonDeleteCertificate, "Successfully deleted unrequired Certificate %q", certName)
		}

		return nil
	}
}

func validateIngressLike(ingLike metav1.Object) field.ErrorList {
	switch o := ingLike.(type) {
	case *networkingv1.Ingress:
		return checkForDuplicateSecretNames(field.NewPath("spec", "tls"), o.Spec.TLS)
	case *gwapi.Gateway:
		return nil
	default:
		panic(fmt.Errorf("programmer mistake: validateIngressLike can't handle %T, expected Ingress or Gateway", ingLike))
	}
}

func checkForDuplicateSecretNames(path *field.Path, tlsBlocks []networkingv1.IngressTLS) field.ErrorList {
	var errs field.ErrorList
	// We can't let two TLS blocks share the same secretName because we decided
	// to create one Certificate for each TLS block. For example:
	//
	//   kind: Ingress
	//   spec:
	//     tls:
	//       - hosts: [example.com]
	//         secretName: example-tls
	//       - hosts: [www.example.com]
	//         secretName: example-tls
	//
	// With this Ingress, cert-manager would create two Certificates with the
	// same name, which would fail.
	//
	// We keep track of the order of the secret names due to Go iterating on
	// maps in a non-deterministic way. We also keep track of each secretName's
	// JSON path just so that we can give a nice error message.
	var secretNames []string
	secretPaths := make(map[string][]*field.Path)
	for i, tls := range tlsBlocks {
		if _, already := secretPaths[tls.SecretName]; !already {
			secretNames = append(secretNames, tls.SecretName)
		}
		secretPaths[tls.SecretName] = append(secretPaths[tls.SecretName], path.Index(i).Child("secretName"))
	}

	for _, name := range secretNames {
		paths := secretPaths[name]
		if len(paths) > 1 {
			// We could use field.Duplicate, but that would prevent us from
			// giving details as to what this duplicate is about.
			errs = append(errs, field.Invalid(paths[0], name,
				fmt.Sprintf("this secret name must only appear in a single TLS entry but is also used in %s", paths[1])))
		}
	}

	return errs
}

func validateIngressTLSBlock(path *field.Path, tlsBlock networkingv1.IngressTLS) field.ErrorList {
	var errs field.ErrorList

	if len(tlsBlock.Hosts) == 0 {
		errs = append(errs, field.Required(path.Child("hosts"), ""))
	}
	if tlsBlock.SecretName == "" {
		errs = append(errs, field.Required(path.Child("secretName"), ""))
	}

	return errs
}

func validateGatewayListenerBlock(path *field.Path, l gwapi.Listener, ingLike metav1.Object) field.ErrorList {
	var errs field.ErrorList

	if l.Hostname == nil || *l.Hostname == "" {
		errs = append(errs, field.Required(path.Child("hostname"), "the hostname cannot be empty"))
	}

	if l.TLS == nil {
		errs = append(errs, field.Required(path.Child("tls"), "the TLS block cannot be empty"))
		return errs
	}

	if len(l.TLS.CertificateRefs) == 0 {
		errs = append(errs, field.Required(path.Child("tls").Child("certificateRef"),
			"listener has no certificateRefs"))
	} else {
		// check that each CertificateRef is valid
		for i, secretRef := range l.TLS.CertificateRefs {
			if *secretRef.Group != "core" && *secretRef.Group != "" {
				errs = append(errs, field.NotSupported(path.Child("tls").Child("certificateRef").Index(i).Child("group"),
					*secretRef.Group, []string{"core", ""}))
			}

			if *secretRef.Kind != "Secret" && *secretRef.Kind != "" {
				errs = append(errs, field.NotSupported(path.Child("tls").Child("certificateRef").Index(i).Child("kind"),
					*secretRef.Kind, []string{"Secret", ""}))
			}

			if secretRef.Namespace != nil && string(*secretRef.Namespace) != ingLike.GetNamespace() {
				errs = append(errs, field.Invalid(path.Child("tls").Child("certificateRef").Index(i).Child("namespace"),
					*secretRef.Namespace, "cross-namespace secret references are not allowed in listeners"))
			}
		}
	}

	if l.TLS.Mode == nil {
		errs = append(errs, field.Required(path.Child("tls").Child("mode"),
			"the mode field is required"))
	} else if *l.TLS.Mode != gwapi.TLSModeTerminate {
		errs = append(errs, field.NotSupported(path.Child("tls").Child("mode"),
			*l.TLS.Mode, []string{string(gwapi.TLSModeTerminate)}))
	}

	return errs
}

func buildCertificates(
	rec record.EventRecorder,
	log logr.Logger,
	cmLister cmlisters.CertificateLister,
	ingLike metav1.Object,
	issuerName, issuerKind, issuerGroup string,
) (newCrts, updateCrts []*cmapi.Certificate, _ error) {
	tlsHosts := make(map[corev1.ObjectReference][]string)
	switch ingLike := ingLike.(type) {
	case *networkingv1.Ingress:
		for i, tls := range ingLike.Spec.TLS {
			path := field.NewPath("spec", "tls").Index(i)
			err := validateIngressTLSBlock(path, tls).ToAggregate()
			if err != nil {
				rec.Eventf(ingLike, corev1.EventTypeWarning, reasonBadConfig, "Skipped a TLS block: "+err.Error())
				continue
			}
			tlsHosts[corev1.ObjectReference{
				Namespace: ingLike.Namespace,
				Name:      tls.SecretName,
			}] = tls.Hosts
		}
	case *gwapi.Gateway:
		for i, l := range ingLike.Spec.Listeners {
			// TLS is only supported for a limited set of protocol types: https://gateway-api.sigs.k8s.io/guides/tls/#listeners-and-tls
			if l.Protocol != gwapi.HTTPSProtocolType && l.Protocol != gwapi.TLSProtocolType {
				continue
			}

			err := validateGatewayListenerBlock(field.NewPath("spec", "listeners").Index(i), l, ingLike).ToAggregate()
			if err != nil {
				rec.Eventf(ingLike, corev1.EventTypeWarning, reasonBadConfig, "Skipped a listener block: "+err.Error())
				continue
			}

			for _, certRef := range l.TLS.CertificateRefs {
				secretRef := corev1.ObjectReference{
					Name: string(certRef.Name),
				}
				if certRef.Namespace != nil {
					secretRef.Namespace = string(*certRef.Namespace)
				} else {
					secretRef.Namespace = ingLike.GetNamespace()
				}
				// Gateway API hostname explicitly disallows IP addresses, so this
				// should be OK.
				tlsHosts[secretRef] = append(tlsHosts[secretRef], string(*l.Hostname))
			}
		}
	default:
		return nil, nil, fmt.Errorf("buildCertificates: expected ingress or gateway, got %T", ingLike)
	}

	for secretRef, hosts := range tlsHosts {
		existingCrt, err := cmLister.Certificates(secretRef.Namespace).Get(secretRef.Name)
		if !apierrors.IsNotFound(err) && err != nil {
			return nil, nil, err
		}

		var controllerGVK schema.GroupVersionKind
		switch ingLike.(type) {
		case *networkingv1.Ingress:
			controllerGVK = ingressV1GVK
		case *gwapi.Gateway:
			controllerGVK = gatewayGVK
		}

		var (
			ipAddress, dnsNames []string
		)
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				ipAddress = append(ipAddress, h)
			} else {
				dnsNames = append(dnsNames, h)
			}
		}

		crt := &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:            secretRef.Name,
				Namespace:       secretRef.Namespace,
				Labels:          ingLike.GetLabels(),
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ingLike, controllerGVK)},
			},
			Spec: cmapi.CertificateSpec{
				DNSNames:    dnsNames,
				IPAddresses: ipAddress,
				SecretName:  secretRef.Name,
				IssuerRef: cmmeta.ObjectReference{
					Name:  issuerName,
					Kind:  issuerKind,
					Group: issuerGroup,
				},
				Usages: cmapi.DefaultKeyUsages(),
			},
		}

		switch o := ingLike.(type) {
		case *networkingv1.Ingress:
			ingLike = o.DeepCopy()
		case *gwapi.Gateway:
			ingLike = o.DeepCopy()
		}
		setIssuerSpecificConfig(crt, ingLike)

		if err := translateAnnotations(crt, ingLike.GetAnnotations()); err != nil {
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

			if !metav1.IsControlledBy(existingCrt, ingLike) {
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

			setIssuerSpecificConfig(crt, ingLike)

			updateCrts = append(updateCrts, updateCrt)
		} else {

			newCrts = append(newCrts, crt)
		}
	}
	return newCrts, updateCrts, nil
}

func findCertificatesToBeRemoved(certs []*cmapi.Certificate, ingLike metav1.Object) []string {
	var toBeRemoved []string
	for _, crt := range certs {
		if !metav1.IsControlledBy(crt, ingLike) {
			continue
		}
		if !secretNameUsedIn(crt.Spec.SecretName, ingLike) {
			toBeRemoved = append(toBeRemoved, crt.Name)
		}
	}
	return toBeRemoved
}

func secretNameUsedIn(secretName string, ingLike metav1.Object) bool {
	switch o := ingLike.(type) {
	case *networkingv1.Ingress:
		for _, tls := range o.Spec.TLS {
			if secretName == tls.SecretName {
				return true
			}
		}
	case *gwapi.Gateway:
		for _, l := range o.Spec.Listeners {
			if l.TLS == nil {
				continue
			}
			for _, certRef := range l.TLS.CertificateRefs {
				if secretName == string(certRef.Name) {
					return true
				}
			}
		}
	}

	return false
}

// certNeedsUpdate checks and returns true if two Certificates differ.
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

	if a.Spec.RevisionHistoryLimit != b.Spec.RevisionHistoryLimit {
		return true
	}

	var aAlgorithm, bAlgorithm cmapi.PrivateKeyAlgorithm
	if a.Spec.PrivateKey != nil && a.Spec.PrivateKey.Algorithm != "" {
		aAlgorithm = a.Spec.PrivateKey.Algorithm
	}

	if b.Spec.PrivateKey != nil && b.Spec.PrivateKey.Algorithm != "" {
		bAlgorithm = b.Spec.PrivateKey.Algorithm
	}

	if aAlgorithm != bAlgorithm {
		return true
	}

	var aEncoding, bEncoding cmapi.PrivateKeyEncoding
	if a.Spec.PrivateKey != nil && a.Spec.PrivateKey.Encoding != "" {
		aEncoding = a.Spec.PrivateKey.Encoding
	}

	if b.Spec.PrivateKey != nil && b.Spec.PrivateKey.Encoding != "" {
		bEncoding = b.Spec.PrivateKey.Encoding
	}

	if aEncoding != bEncoding {
		return true
	}

	var aRotationPolicy, bRotationPolicy cmapi.PrivateKeyRotationPolicy
	if a.Spec.PrivateKey != nil && a.Spec.PrivateKey.RotationPolicy != "" {
		aRotationPolicy = a.Spec.PrivateKey.RotationPolicy
	}

	if b.Spec.PrivateKey != nil && b.Spec.PrivateKey.RotationPolicy != "" {
		bRotationPolicy = b.Spec.PrivateKey.RotationPolicy
	}

	if aRotationPolicy != bRotationPolicy {
		return true
	}

	// for Ed25519 private key size is ignored
	if aAlgorithm != cmapi.Ed25519KeyAlgorithm {
		var aSize, bSize int
		if a.Spec.PrivateKey != nil && a.Spec.PrivateKey.Size != 0 {
			aSize = a.Spec.PrivateKey.Size
		}

		if b.Spec.PrivateKey != nil && b.Spec.PrivateKey.Size != 0 {
			bSize = b.Spec.PrivateKey.Size
		}

		if aSize != bSize {
			return true
		}
	}

	return false
}

// setIssuerSpecificConfig configures given Certificate's annotation by reading
// two Ingress-specific annotations.
//
// (1)
// The edit-in-place Ingress annotation allows the use of Ingress
// controllers that map a single IP address to a single Ingress
// resource, such as the GCE ingress controller. The following
// annotation on an Ingress named "my-ingress":
//
//	acme.cert-manager.io/http01-edit-in-place: "true"
//
// configures the Certificate with two annotations:
//
//	acme.cert-manager.io/http01-override-ingress-name: my-ingress
//	cert-manager.io/issue-temporary-certificate: "true"
//
// (2)
// The ingress-class Ingress annotation allows users to override the
// Issuer's acme.solvers[0].http01.ingress.class. For example, on the
// Ingress:
//
//	acme.cert-manager.io/http01-ingress-class: traefik
//
// configures the Certificate using the override-ingress-class annotation:
//
//	acme.cert-manager.io/http01-override-ingress-class: traefik
func setIssuerSpecificConfig(crt *cmapi.Certificate, ingLike metav1.Object) {
	ingAnnotations := ingLike.GetAnnotations()
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
		crt.Annotations[cmacme.ACMECertificateHTTP01IngressNameOverride] = ingLike.GetName()
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

	ingLike.SetAnnotations(ingAnnotations)
}

// hasShimAnnotation returns true if the given ingress-like resource contains
// one of the trigger annotations:
//
//	cert-manager.io/issuer
//	cert-manager.io/cluster-issuer
//
// The autoCertificateAnnotations can also be used to customize additional
// annotations to trigger a Certificate shim. For example, for Ingress
// resources, we default autoCertificateAnnotations to:
//
//	kubernetes.io/tls-acme: "true"
func hasShimAnnotation(ingLike metav1.Object, autoCertificateAnnotations []string) bool {
	annotations := ingLike.GetAnnotations()
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

// isDeletedInForeground returns true if the given ingressLike resource
// contains either
//
// metadata.deletionTimestamp, or
// metadata.finalizers having one of the values as foregroundDeletion
//
// which indicates that the resource is being deleted via foreground cascading.
// Ref: https://kubernetes.io/docs/concepts/architecture/garbage-collection/#foreground-deletion
func isDeletedInForeground(ingLike metav1.Object) bool {
	deletionTimestamp := ingLike.GetDeletionTimestamp()
	finalizers := ingLike.GetFinalizers()
	foregroundDeletion := false

	for _, v := range finalizers {
		if v == metav1.FinalizerDeleteDependents {
			foregroundDeletion = true
		}
	}

	return deletionTimestamp != nil || foregroundDeletion
}

// issuerForIngressLike determines the Issuer that should be specified on a
// Certificate created for the given ingress-like resource. If one is not set,
// the default issuer given to the controller is used. We look up the following
// Ingress annotations:
//
//	cert-manager.io/cluster-issuer
//	cert-manager.io/issuer
//	cert-manager.io/issuer-kind
//	cert-manager.io/issuer-group
func issuerForIngressLike(defaults controller.IngressShimOptions, ingLike metav1.Object) (name, kind, group string, err error) {
	var errs []string

	name = defaults.DefaultIssuerName
	kind = defaults.DefaultIssuerKind
	group = defaults.DefaultIssuerGroup

	annotations := ingLike.GetAnnotations()

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
