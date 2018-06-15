// Package localmanifests implements a control loop that watches manifest files
// on disk and manually forces them through their respective control loops.
//
// Similar to the kubelet's 'static manifests' concept, it allows cert-manager
// to process resources before it is able to interact with its own API.
// This is especially useful, and originally designed for, bootstrapping the
// Validating/Mutating webhook components of cert-manager to solve the
// chicken-egg problem.
package localmanifests

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/jetstack/cert-manager/pkg/api"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cminformers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions/certmanager/v1alpha1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/util"
)

// Controller is the localmanifest controller
type Controller struct {
	cmClient clientset.Interface

	issuerInformer        cminformers.IssuerInformer
	clusterIssuerInformer cminformers.ClusterIssuerInformer
	certificateInformer   cminformers.CertificateInformer

	// path to the directory containing the static manifests
	manifestsPath string

	// queue is a queue of filepaths to process
	queue workqueue.RateLimitingInterface
}

// Run will start the local manifest controller.
// When run, the 'manifestsPath' will be read. Each file in the directory will
// be queued to be processed, and will keep being requeued until it has been
// successfully synced.
// In future, we may use something like inotify to watch for changes on disk to
// these resources.
//
// The 'workers' parameter is ignored, and only one manifest will be processed
// at a time.
func (c *Controller) Run(_ int, stopCh <-chan struct{}) error {
	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*2, time.Minute*1), "localmanifests")

	// wait for all the informer caches we depend to sync
	if !cache.WaitForCacheSync(stopCh,
		c.certificateInformer.Informer().HasSynced,
		c.clusterIssuerInformer.Informer().HasSynced,
		c.issuerInformer.Informer().HasSynced,
	) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	files, err := ioutil.ReadDir(c.manifestsPath)
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		// load each file into the workqueue
		fp := filepath.Join(c.manifestsPath, f.Name())
		c.queue.Add(fp)
	}

	workers := 1
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go wait.Until(func() { defer wg.Done(); c.work(stopCh) }, time.Second, stopCh)
	}

	<-stopCh
	glog.V(4).Infof("Shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	glog.V(4).Infof("Waiting for workers to exit...")
	wg.Wait()
	glog.V(4).Infof("Workers exited.")

	return nil
}

// work will read paths of the queue and run processNextWorkItem.
// If processing fails, the item will be re-queued with the rate limit applied.
func (c *Controller) work(stopCh <-chan struct{}) {
	glog.V(4).Infof("Starting %q worker", controllerName)
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		var key string
		err := func(obj interface{}) error {
			defer c.queue.Done(obj)
			var ok bool
			if key, ok = obj.(string); !ok {
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = util.ContextWithStopCh(ctx, stopCh)
			glog.Infof("%s controller: syncing item '%s'", controllerName, key)
			if err := c.processNextWorkItem(ctx, key); err != nil {
				return err
			}
			c.queue.Forget(obj)
			return nil
		}(obj)

		if err != nil {
			glog.Errorf("%s controller: Re-queuing item %q due to error processing: %s", controllerName, key, err.Error())
			c.queue.AddRateLimited(obj)
			continue
		}

		glog.Infof("%s controller: Finished processing work item %q", controllerName, key)
	}
	glog.V(4).Infof("Exiting %q worker loop", controllerName)
}

func (c *Controller) processNextWorkItem(ctx context.Context, path string) error {
	glog.Infof("Processing local manifest %q", path)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		glog.Infof("Error reading local manifest %q: %v", path, err)
		return err
	}

	decoder := api.Codecs.UniversalDeserializer()
	obj, gvk, err := decoder.Decode(data, nil, nil)
	if err != nil {
		glog.Infof("Error decoding manifest %q: %v", path, err)
		return err
	}

	glog.V(4).Infof("Read GVK: %v, obj: %v", gvk, obj)
	return c.runController(gvk, obj)
}

func (c *Controller) runController(gvk *schema.GroupVersionKind, obj runtime.Object) error {
	if gvk.Group != "certmanager.k8s.io" {
		glog.Errorf("Invalid group for local manifest resource: %q", gvk.Group)
		return nil
	}
	if gvk.Version != "v1alpha1" {
		glog.Errorf("Invalid version for local manifest resource: %q", gvk.Version)
		return nil
	}

	var err error
	var addFn func(interface{}) error
	switch gvk.Kind {
	case v1alpha1.CertificateKind:
		err = c.persistCertificate(obj)
		addFn = c.certificateInformer.Informer().GetIndexer().Add
	case v1alpha1.IssuerKind:
		err = c.persistIssuer(obj)
		addFn = c.issuerInformer.Informer().GetIndexer().Add
	case v1alpha1.ClusterIssuerKind:
		err = c.persistClusterIssuer(obj)
		addFn = c.clusterIssuerInformer.Informer().GetIndexer().Add
	default:
		glog.Errorf("Invalid kind for local manifest resource: %q", gvk.Kind)
		return nil
	}
	// if persisting the object to the API is successful, we return as everything
	// is already bootstrapped.
	if err == nil {
		return nil
	}

	// otherwise, manually add the resource to the lister so it will be processed
	// and return an error
	err = addFn(obj)
	if err != nil {
		return err
	}

	return fmt.Errorf("failed to persist resource to API - retrying")
}

func (c *Controller) persistCertificate(obj runtime.Object) error {
	crt, ok := obj.(*v1alpha1.Certificate)
	if !ok {
		return fmt.Errorf("resource is not a Certificate")
	}

	existingCrt, err := c.certificateInformer.Lister().Certificates(crt.Namespace).Get(crt.Name)
	if err == nil && existingCrt.ResourceVersion != "" {
		// we want to overwrite the contents of the Certificate, and this is a
		// required field on update
		crt.ResourceVersion = existingCrt.ResourceVersion
		_, err := c.cmClient.CertmanagerV1alpha1().Certificates(crt.Namespace).Update(crt)
		if err != nil {
			return err
		}
		return nil
	}

	_, err = c.cmClient.CertmanagerV1alpha1().Certificates(crt.Namespace).Create(crt)
	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) persistIssuer(obj runtime.Object) error {
	iss, ok := obj.(*v1alpha1.Issuer)
	if !ok {
		return fmt.Errorf("resource is not an Issuer")
	}

	existingIss, err := c.issuerInformer.Lister().Issuers(iss.Namespace).Get(iss.Name)
	if err == nil && existingIss.ResourceVersion != "" {
		// we want to overwrite the contents of the Issuer, and this is a
		// required field on update
		iss.ResourceVersion = existingIss.ResourceVersion
		_, err := c.cmClient.CertmanagerV1alpha1().Issuers(iss.Namespace).Update(iss)
		if err != nil {
			return err
		}
		return nil
	}

	_, err = c.cmClient.CertmanagerV1alpha1().Issuers(iss.Namespace).Create(iss)
	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) persistClusterIssuer(obj runtime.Object) error {
	iss, ok := obj.(*v1alpha1.ClusterIssuer)
	if !ok {
		return fmt.Errorf("resource is not a ClusterIssuer")
	}

	existingIss, err := c.clusterIssuerInformer.Lister().Get(iss.Name)
	if err == nil && existingIss.ResourceVersion != "" {
		// we want to overwrite the contents of the ClusterIssuer, and this is a
		// required field on update
		iss.ResourceVersion = existingIss.ResourceVersion
		_, err := c.cmClient.CertmanagerV1alpha1().ClusterIssuers().Update(iss)
		if err != nil {
			return err
		}
		return nil
	}

	_, err = c.cmClient.CertmanagerV1alpha1().ClusterIssuers().Create(iss)
	if err != nil {
		return err
	}

	return nil
}

const (
	controllerName = "localmanifests"
)

func init() {
	controllerpkg.Register(controllerName, func(ctx *controllerpkg.Context) controllerpkg.Interface {
		return (&Controller{
			cmClient:              ctx.CMClient,
			certificateInformer:   ctx.SharedInformerFactory.Certmanager().V1alpha1().Certificates(),
			issuerInformer:        ctx.SharedInformerFactory.Certmanager().V1alpha1().Issuers(),
			clusterIssuerInformer: ctx.SharedInformerFactory.Certmanager().V1alpha1().ClusterIssuers(),
			manifestsPath:         ctx.LocalManifestsDir,
		}).Run
	})
}
