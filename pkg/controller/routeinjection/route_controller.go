package routeinjection

import (
	"context"
	"reflect"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	routev1 "github.com/openshift/api/route/v1"
	util "github.com/jetstack/pkg/controller"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const certAnnotation = util.AnnotationBase + "/certs-from-secret"
const destCAAnnotation = util.AnnotationBase + "/destinationCA-from-secret"

var log = logf.Log.WithName("controller_route")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new Route Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileRoute{client: mgr.GetClient(), scheme: mgr.GetScheme(), recorder: mgr.GetRecorder("route-controller")}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("route-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// this will filter routes that have the annotation and on update only if the annotation is changed.
	isAnnotatedAndSecureRoute := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			newRoute, ok := e.ObjectNew.DeepCopyObject().(*routev1.Route)
			if !ok || newRoute.Spec.TLS == nil || !(newRoute.Spec.TLS.Termination == "edge" || newRoute.Spec.TLS.Termination == "reencrypt") {
				return false
			}
			oldSecret, _ := e.MetaOld.GetAnnotations()[certAnnotation]
			newSecret, _ := e.MetaNew.GetAnnotations()[certAnnotation]
			if oldSecret != newSecret {
				return true
			}
			oldRoute, _ := e.ObjectOld.DeepCopyObject().(*routev1.Route)
			if newSecret != "" {
				if newRoute.Spec.TLS.Key != oldRoute.Spec.TLS.Key {
					return true
				}
				if newRoute.Spec.TLS.Certificate != oldRoute.Spec.TLS.Certificate {
					return true
				}
				if newRoute.Spec.TLS.CACertificate != oldRoute.Spec.TLS.CACertificate {
					return true
				}
			}
			oldCASecret, _ := e.MetaOld.GetAnnotations()[destCAAnnotation]
			newCASecret, _ := e.MetaNew.GetAnnotations()[destCAAnnotation]
			if newCASecret != oldCASecret {
				return true
			}
			if newCASecret != "" {
				if newRoute.Spec.TLS.DestinationCACertificate != oldRoute.Spec.TLS.DestinationCACertificate {
					return true
				}
			}
			return false
		},
		CreateFunc: func(e event.CreateEvent) bool {
			route, ok := e.Object.DeepCopyObject().(*routev1.Route)
			if !ok || route.Spec.TLS == nil || !(route.Spec.TLS.Termination == "edge" || route.Spec.TLS.Termination == "reencrypt") {
				return false
			}
			_, ok = e.Meta.GetAnnotations()[certAnnotation]
			_, okca := e.Meta.GetAnnotations()[destCAAnnotation]
			return ok || okca
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},

		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}

	// Watch for changes to primary resource Route
	err = c.Watch(&source.Kind{Type: &routev1.Route{}}, &handler.EnqueueRequestForObject{}, isAnnotatedAndSecureRoute)
	if err != nil {
		return err
	}

	// this will filter new secrets and secrets where the content changed
	// secret that are actually referenced by routes will be filtered by the handler
	isContentChanged := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSecret, ok := e.ObjectOld.(*corev1.Secret)
			if !ok {
				return false
			}
			newSecret, ok := e.ObjectNew.(*corev1.Secret)
			if !ok {
				return false
			}
			if newSecret.Type != util.TLSSecret {
				return false
			}
			return !reflect.DeepEqual(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) ||
				!reflect.DeepEqual(newSecret.Data[util.Key], oldSecret.Data[util.Key]) ||
				!reflect.DeepEqual(newSecret.Data[util.CA], oldSecret.Data[util.CA])
		},
		CreateFunc: func(e event.CreateEvent) bool {
			secret, ok := e.Object.(*corev1.Secret)
			if !ok {
				return false
			}
			if secret.Type != util.TLSSecret {
				return false
			}
			return true
		},
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner Route
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &enqueueRequestForReferecingRoutes{
		Client: mgr.GetClient(),
	}, isContentChanged)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileRoute{}

// ReconcileRoute reconciles a Route object
type ReconcileRoute struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	recorder record.EventRecorder
}

// Reconcile reads that state of the cluster for a Route object and makes changes based on the state read
// and what is in the Route.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileRoute) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Route")

	// Fetch the Route instance
	instance := &routev1.Route{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	if instance.Spec.TLS == nil {
		return reconcile.Result{}, nil
	}
	secretName, ok := instance.GetAnnotations()[certAnnotation]
	caSecretName, okca := instance.GetAnnotations()[destCAAnnotation]
	shouldUpdate := false
	if !ok {
		if instance.Spec.TLS.Key != "" {
			instance.Spec.TLS.Key = ""
			shouldUpdate = true
		}
		if instance.Spec.TLS.Certificate != "" {
			instance.Spec.TLS.Certificate = ""
			shouldUpdate = true
		}
		if instance.Spec.TLS.CACertificate != "" {
			instance.Spec.TLS.CACertificate = ""
			shouldUpdate = true
		}

	} else {
		secret := &corev1.Secret{}
		err = r.client.Get(context.TODO(), types.NamespacedName{
			Namespace: instance.GetNamespace(),
			Name:      secretName,
		}, secret)
		if err != nil {
			log.Error(err, "unable to find referenced secret", "secret", secretName)
			return r.manageError(err, instance)
		}
		shouldUpdate = shouldUpdate || populateRouteWithCertifcates(instance, secret)
	}
	if !okca {
		if instance.Spec.TLS.DestinationCACertificate != "" {
			instance.Spec.TLS.DestinationCACertificate = ""
			shouldUpdate = true
		}
	} else {
		secret := &corev1.Secret{}
		err = r.client.Get(context.TODO(), types.NamespacedName{
			Namespace: instance.GetNamespace(),
			Name:      caSecretName,
		}, secret)
		if err != nil {
			log.Error(err, "unable to find referenced ca secret", "secret", secretName)
			return r.manageError(err, instance)
		}
		shouldUpdate = shouldUpdate || populateRouteDestCA(instance, secret)
	}

	if shouldUpdate {
		err = r.client.Update(context.TODO(), instance)
		if err != nil {
			log.Error(err, "unable to update route", "route", instance)
			return r.manageError(err, instance)
		}
	}

	// if we are here we know it's because a route was create/modified or its referenced secret was created/modified
	// therefore the only think we need to do is to update the route certificates

	return reconcile.Result{}, nil
}

func matchSecret(c client.Client, secret types.NamespacedName) ([]routev1.Route, error) {
	routeList := &routev1.RouteList{}
	err := c.List(context.TODO(), &client.ListOptions{
		Namespace: secret.Namespace,
	}, routeList)
	if err != nil {
		log.Error(err, "unable to list routes for this namespace: ", "namespace", secret.Namespace)
		return []routev1.Route{}, err
	}
	result := []routev1.Route{}
	for _, route := range routeList.Items {
		if secretName := route.GetAnnotations()[certAnnotation]; secretName == secret.Name && route.Spec.TLS != nil {
			result = append(result, route)
			break
		}
		if secretName := route.GetAnnotations()[destCAAnnotation]; secretName == secret.Name && route.Spec.TLS != nil {
			result = append(result, route)
			break
		}
	}
	return result, nil
}

type enqueueRequestForReferecingRoutes struct {
	client.Client
}

// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingRoutes) Create(evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	routes, _ := matchSecret(e.Client, types.NamespacedName{
		Name:      evt.Meta.GetName(),
		Namespace: evt.Meta.GetNamespace(),
	})
	for _, route := range routes {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: route.GetNamespace(),
			Name:      route.GetName(),
		}})
	}
}

// Update implements EventHandler
// trigger a router reconcile event for those routes that reference this secret
func (e *enqueueRequestForReferecingRoutes) Update(evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	routes, _ := matchSecret(e.Client, types.NamespacedName{
		Name:      evt.MetaNew.GetName(),
		Namespace: evt.MetaNew.GetNamespace(),
	})
	for _, route := range routes {
		q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: route.GetNamespace(),
			Name:      route.GetName(),
		}})
	}
}

// Delete implements EventHandler
func (e *enqueueRequestForReferecingRoutes) Delete(evt event.DeleteEvent, q workqueue.RateLimitingInterface) {
	return
}

// Generic implements EventHandler
func (e *enqueueRequestForReferecingRoutes) Generic(evt event.GenericEvent, q workqueue.RateLimitingInterface) {
	return
}

func populateRouteWithCertifcates(route *routev1.Route, secret *corev1.Secret) bool {
	shouldUpdate := false
	if route.Spec.TLS.Termination == "edge" || route.Spec.TLS.Termination == "reencrypt" {
		// here we need to replace the terminating certifciate
		if value, ok := secret.Data[util.Key]; ok && len(value) != 0 {
			if route.Spec.TLS.Key != string(value) {
				route.Spec.TLS.Key = string(value)
				shouldUpdate = true
			}
		}
		if value, ok := secret.Data[util.Cert]; ok && len(value) != 0 {
			if route.Spec.TLS.Certificate != string(value) {
				route.Spec.TLS.Certificate = string(value)
				shouldUpdate = true
			}
		}
		if value, ok := secret.Data[util.CA]; ok && len(value) != 0 {
			if route.Spec.TLS.CACertificate != string(value) {
				route.Spec.TLS.CACertificate = string(value)
				shouldUpdate = true
			}
		}
	}
	return shouldUpdate
}

func populateRouteDestCA(route *routev1.Route, secret *corev1.Secret) bool {
	shouldUpdate := false
	if value, ok := secret.Data[util.CA]; ok && len(value) != 0 {
		if route.Spec.TLS.DestinationCACertificate != string(value) {
			route.Spec.TLS.DestinationCACertificate = string(value)
			shouldUpdate = true
		}
	}
	return shouldUpdate
}

func (r *ReconcileRoute) manageError(issue error, instance runtime.Object) (reconcile.Result, error) {
	r.recorder.Event(instance, "Warning", "ProcessingError", issue.Error())
	return reconcile.Result{
		RequeueAfter: time.Minute * 2,
		Requeue:      true,
	}, nil
}
