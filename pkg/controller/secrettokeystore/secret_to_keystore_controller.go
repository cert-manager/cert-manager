package secrettokeystore

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go"
	util "github.com/jetstack/pkg/controller"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_secret_to_keystore")

const javaKeyStoresAnnotation = util.AnnotationBase + "/generate-java-keystores"
const keystorepasswordAnnotation = util.AnnotationBase + "/java-keystore-password"
const defaultpassword = "changeme"
const keystoreName = "keystore.jks"
const truststoreName = "truststore.jks"

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new Secret Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileSecret{client: mgr.GetClient(), scheme: mgr.GetScheme(), recorder: mgr.GetRecorder("secret-to-keystore-controller")}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("secret-to-keystore-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	isAnnotatedSecret := predicate.Funcs{
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
			oldValue, _ := e.MetaOld.GetAnnotations()[javaKeyStoresAnnotation]
			newValue, _ := e.MetaNew.GetAnnotations()[javaKeyStoresAnnotation]
			old := oldValue == "true"
			new := newValue == "true"
			// if the content has changed we trigger is the annotation is there
			if !reflect.DeepEqual(newSecret.Data[util.Cert], oldSecret.Data[util.Cert]) ||
				!reflect.DeepEqual(newSecret.Data[util.Key], oldSecret.Data[util.Key]) ||
				!reflect.DeepEqual(newSecret.Data[util.CA], oldSecret.Data[util.CA]) {
				return new
			}
			// otherwise we trigger if the annotation has changed
			return old != new
		},
		CreateFunc: func(e event.CreateEvent) bool {
			secret, ok := e.Object.(*corev1.Secret)
			if !ok {
				return false
			}
			if secret.Type != util.TLSSecret {
				return false
			}
			value, _ := e.Meta.GetAnnotations()[javaKeyStoresAnnotation]
			return value == "true"
		},
	}

	// Watch for changes to primary resource Secret
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, isAnnotatedSecret)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileSecret{}

// ReconcileSecret reconciles a Secret object
type ReconcileSecret struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	recorder record.EventRecorder
}

// Reconcile reads that state of the cluster for a Secret object and makes changes based on the state read
// and what is in the Secret.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileSecret) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Secret")

	// Fetch the Secret instance
	instance := &corev1.Secret{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}
	value, _ := instance.GetAnnotations()[javaKeyStoresAnnotation]
	if value == "true" {
		if value, ok := instance.Data[util.Cert]; ok && len(value) != 0 {
			if value, ok := instance.Data[util.Key]; ok && len(value) != 0 {
				keyStore, err := getKeyStoreFromSecret(instance)
				if err != nil {
					log.Error(err, "unable to create keystore from secret", "secret", instance.Namespace+"/"+instance.Name)
					return reconcile.Result{}, err
				}
				instance.Data[keystoreName] = keyStore
			}
		}
		if value, ok := instance.Data[util.CA]; ok && len(value) != 0 {
			trustStore, err := getTrustStoreFromSecret(instance)
			if err != nil {
				log.Error(err, "unable to create truststore from secret", "secret", instance.Namespace+"/"+instance.Name)
				return reconcile.Result{}, err
			}
			instance.Data[truststoreName] = trustStore
		}
	} else {
		delete(instance.Data, keystoreName)
		delete(instance.Data, truststoreName)
	}

	err = r.client.Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, "unable to update secrer", "secret", instance.GetName())
		return r.manageError(err, instance)
	}

	return reconcile.Result{}, nil
}

func getKeyStoreFromSecret(secret *corev1.Secret) ([]byte, error) {
	keyStore := keystore.KeyStore{}
	key, ok := secret.Data[util.Key]
	if !ok {
		return []byte{}, errors.New("tls.key not found")
	}
	crt, ok := secret.Data[util.Cert]
	if !ok {
		return []byte{}, errors.New("tls.crt not found")
	}
	certs := []keystore.Certificate{}
	for p, rest := pem.Decode(crt); p != nil; p, rest = pem.Decode(rest) {
		certs = append(certs, keystore.Certificate{
			Type:    "X.509",
			Content: p.Bytes,
		})
	}
	p, _ := pem.Decode(key)
	if p == nil {
		return []byte{}, errors.New("no block found in key.tls, private key should have at least one pem block")
	}
	if !strings.Contains(p.Type, "PRIVATE KEY") {
		return []byte{}, errors.New("private key block not of type PRIVATE KEY")
	}

	keyStore["alias"] = &keystore.PrivateKeyEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		PrivKey:   p.Bytes,
		CertChain: certs,
	}
	buffer := bytes.Buffer{}
	err := keystore.Encode(&buffer, keyStore, []byte(getPassword(secret)))
	if err != nil {
		log.Error(err, "unable to encode keystore", "keystore", keyStore)
		return []byte{}, err
	}
	return buffer.Bytes(), nil
}

func getTrustStoreFromSecret(secret *corev1.Secret) ([]byte, error) {
	keyStore := keystore.KeyStore{}
	ca, ok := secret.Data[util.CA]
	if !ok {
		return []byte{}, errors.New("ca bundle key not found: ca.crt")
	}
	i := 0
	for p, rest := pem.Decode(ca); p != nil; p, rest = pem.Decode(rest) {
		keyStore["alias"+strconv.Itoa(i)] = &keystore.TrustedCertificateEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: p.Bytes,
			},
		}
	}
	buffer := bytes.Buffer{}
	err := keystore.Encode(&buffer, keyStore, []byte(getPassword(secret)))
	if err != nil {
		log.Error(err, "unable to encode keystore", "keystore", keyStore)
		return []byte{}, err
	}
	return buffer.Bytes(), nil
}

func getPassword(secret *corev1.Secret) string {
	if pwd, ok := secret.GetAnnotations()[keystorepasswordAnnotation]; ok && pwd != "" {
		return pwd
	}
	return defaultpassword
}

func (r *ReconcileSecret) manageError(issue error, instance runtime.Object) (reconcile.Result, error) {
	r.recorder.Event(instance, "Warning", "ProcessingError", issue.Error())
	return reconcile.Result{
		RequeueAfter: time.Minute * 2,
		Requeue:      true,
	}, nil
}
