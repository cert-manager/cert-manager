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

package authority

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	coreclientset "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	cmmeta "github.com/cert-manager/cert-manager/internal/apis/meta"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/cmrand"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

// DynamicAuthority manages a certificate authority stored in a Secret resource
// and provides methods to obtain signed leaf certificates.
// The private key and certificate will be automatically generated, and when
// nearing expiry, the private key and root certificate will be rotated.
type DynamicAuthority struct {
	// Namespace and Name of the Secret resource used to store the authority.
	SecretNamespace, SecretName string

	// RESTConfig used to connect to the apiserver.
	RESTConfig *rest.Config

	// The amount of time the root CA certificate will be valid for.
	// This must be greater than LeafDuration.
	// Defaults to 365d.
	CADuration time.Duration

	// The amount of time leaf certificates signed by this authority will be
	// valid for.
	// This must be less than CADuration.
	// Defaults to 7d.
	LeafDuration time.Duration

	// Logger to write messages to.
	log logr.Logger

	lister corelisters.SecretNamespaceLister
	client coreclientset.SecretInterface

	// PEM-encoded CA certificate and private key bytes
	currentCertData, currentPrivateKeyData []byte
	// signMutex gates access to the certificate and private key data
	signMutex sync.Mutex
	// ensureMutex gates the 'ensureCA' method
	ensureMutex sync.Mutex
	// watchMutex gates access to the slice of watch channels
	watchMutex sync.Mutex
	watches    []chan<- struct{}

	newClient func(c *rest.Config) (kubernetes.Interface, error) // for testing
}

type SignFunc func(template *x509.Certificate) (*x509.Certificate, error)

var _ SignFunc = (&DynamicAuthority{}).Sign

func (d *DynamicAuthority) Run(ctx context.Context) error {
	d.log = logf.FromContext(ctx)
	if d.SecretNamespace == "" {
		return fmt.Errorf("SecretNamespace must be set")
	}
	if d.SecretName == "" {
		return fmt.Errorf("SecretName must be set")
	}
	if d.CADuration == 0 {
		d.CADuration = time.Hour * 24 * 365 // 365d
	}
	if d.LeafDuration == 0 {
		d.LeafDuration = time.Hour * 24 * 7 // 7d
	}

	if d.newClient == nil {
		d.newClient = func(c *rest.Config) (kubernetes.Interface, error) {
			return kubernetes.NewForConfig(c)
		}
	}

	cl, err := d.newClient(d.RESTConfig)
	if err != nil {
		return err
	}

	escapedName := fields.EscapeValue(d.SecretName)
	factory := informers.NewSharedInformerFactoryWithOptions(cl, time.Minute,
		informers.WithNamespace(d.SecretNamespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = "metadata.name=" + escapedName
		}),
	)
	informer := factory.Core().V1().Secrets().Informer()
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    d.handleAdd,
		UpdateFunc: d.handleUpdate,
		DeleteFunc: d.handleDelete,
	}); err != nil {
		return fmt.Errorf("error setting up event handler: %v", err)
	}

	d.lister = factory.Core().V1().Secrets().Lister().Secrets(d.SecretNamespace)
	d.client = cl.CoreV1().Secrets(d.SecretNamespace)

	// start the informers and wait for the cache to sync
	factory.Start(ctx.Done())
	defer factory.Shutdown()

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		if ctx.Err() != nil { // context was cancelled, we are shutting down; so, don't return an error because the informer caches were not yet synced
			return nil
		}

		return fmt.Errorf("failed waiting for informer caches to sync")
	}

	// continuously check the secret resource every 10s in case any events have
	// been  missed that could cause us to get into an idle state where the
	// Secret resource does not exist and so the informers handler functions
	// are not triggered.
	if err := wait.PollUntilContextCancel(ctx, time.Second*10, true, func(ctx context.Context) (done bool, err error) {
		if err := d.ensureCA(ctx); err != nil {
			d.log.Error(err, "error ensuring CA")
		}
		// never return 'done'.
		// this poll only ends when stopCh is closed.
		return false, nil
	}); err != nil {
		if errors.Is(err, context.Canceled) {
			// context was cancelled, return nil
			return nil
		}

		return err
	}

	return nil
}

// Sign will sign the given certificate template using the current version of
// the managed CA.
// It will automatically set the NotBefore and NotAfter times appropriately.
func (d *DynamicAuthority) Sign(template *x509.Certificate) (*x509.Certificate, error) {
	d.signMutex.Lock()
	defer d.signMutex.Unlock()

	if d.currentCertData == nil || d.currentPrivateKeyData == nil {
		return nil, fmt.Errorf("no tls.Certificate available yet, try again later")
	}

	// tls.X509KeyPair performs a number of verification checks against the
	// keypair, so we run it to verify the certificate and private key are
	// valid.
	_, err := tls.X509KeyPair(d.currentCertData, d.currentPrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed verifying CA keypair: %v", err)
	}

	caCert, err := pki.DecodeX509CertificateBytes(d.currentCertData)
	if err != nil {
		return nil, fmt.Errorf("failed decoding CA certificate: %v", err)
	}

	caPk, err := pki.DecodePrivateKeyBytes(d.currentPrivateKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed decoding CA private key: %v", err)
	}

	serialNumber, err := cmrand.SerialNumber()
	if err != nil {
		return nil, err
	}

	template.Version = 3
	template.SerialNumber = serialNumber
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(d.LeafDuration)

	// explicitly handle the case of the root CA certificate being expired
	if caCert.NotAfter.Before(template.NotBefore) {
		return nil, fmt.Errorf("internal error: CA certificate has expired, try again later")
	}
	// don't allow leaf certificates to be valid longer than their parents
	if caCert.NotAfter.Before(template.NotAfter) {
		template.NotAfter = caCert.NotAfter
	}

	_, cert, err := pki.SignCertificate(template, caCert, template.PublicKey.(crypto.PublicKey), caPk)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// WatchRotation will return a channel that fires notifications if the CA
// certificate is rotated/updated.
// This can be used to automatically trigger rotation of leaf certificates
// when the root CA changes.
func (d *DynamicAuthority) WatchRotation(output chan<- struct{}) {
	d.watchMutex.Lock()
	defer d.watchMutex.Unlock()

	// Add the output channel to the list of watches
	d.watches = append(d.watches, output)
}

func (d *DynamicAuthority) StopWatchingRotation(output chan<- struct{}) {
	d.watchMutex.Lock()
	defer d.watchMutex.Unlock()

	// Remove the output channel from the list of watches
	for i, c := range d.watches {
		if c == output {
			d.watches = append(d.watches[:i], d.watches[i+1:]...)
			return
		}
	}
}

func (d *DynamicAuthority) ensureCA(ctx context.Context) error {
	d.ensureMutex.Lock()
	defer d.ensureMutex.Unlock()

	s, err := d.lister.Get(d.SecretName)
	if apierrors.IsNotFound(err) {
		d.log.V(logf.InfoLevel).Info("Will regenerate CA", "reason", "CA secret not found")
		return d.regenerateCA(ctx, nil)
	}
	if err != nil {
		return err
	}
	if required, reason := caRequiresRegeneration(s); required {
		d.log.V(logf.InfoLevel).Info("Will regenerate CA", "reason", reason)
		return d.regenerateCA(ctx, s.DeepCopy())
	}
	d.notifyWatches(s.Data[corev1.TLSCertKey], s.Data[corev1.TLSPrivateKeyKey])
	return nil
}

func (d *DynamicAuthority) notifyWatches(newCertData, newPrivateKeyData []byte) {
	if bytes.Equal(d.currentCertData, newCertData) && bytes.Equal(d.currentPrivateKeyData, newPrivateKeyData) {
		// do nothing if the data has not changed
		return
	}

	d.log.V(logf.InfoLevel).Info("Detected change in CA secret data, update current CA data and notify watches")

	func() {
		d.signMutex.Lock()
		defer d.signMutex.Unlock()
		d.currentCertData = newCertData
		d.currentPrivateKeyData = newPrivateKeyData
	}()

	func() {
		d.watchMutex.Lock()
		defer d.watchMutex.Unlock()
		for _, ch := range d.watches {
			// the watch channels have a buffer of 1 - drop events to slow
			// consumers
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
}

// caRequiresRegeneration will check data in a Secret resource and return true
// if the CA needs to be regenerated for any reason.
func caRequiresRegeneration(s *corev1.Secret) (bool, string) {
	if s.Data == nil {
		return true, "Missing data in CA secret."
	}
	caData := s.Data[cmmeta.TLSCAKey]
	pkData := s.Data[corev1.TLSPrivateKeyKey]
	certData := s.Data[corev1.TLSCertKey]
	if len(caData) == 0 || len(pkData) == 0 || len(certData) == 0 {
		return true, "Missing data in CA secret."
	}
	// ensure that the ca.crt and tls.crt keys are equal
	if !bytes.Equal(caData, certData) {
		return true, "Different data in ca.crt and tls.crt."
	}
	cert, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return true, "Failed to parse data in CA secret."
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true, "Internal error parsing x509 certificate."
	}
	if !x509Cert.IsCA {
		return true, "Stored certificate is not marked as a CA."
	}
	// renew the root CA when the current one is 2/3 of the way through its life
	if time.Until(x509Cert.NotAfter) < (x509Cert.NotAfter.Sub(x509Cert.NotBefore) / 3) {
		return true, "CA certificate is nearing expiry."
	}

	return false, ""
}

// regenerateCA will regenerate and store a new CA.
// If the provided Secret is nil, a new secret resource will be Created.
// Otherwise, the provided resource will be modified and Updated.
func (d *DynamicAuthority) regenerateCA(ctx context.Context, s *corev1.Secret) error {
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return err
	}
	pkBytes, err := pki.EncodePrivateKey(pk, cmapi.PKCS8)
	if err != nil {
		return err
	}

	serialNumber, err := cmrand.SerialNumber()
	if err != nil {
		return err
	}

	cert := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.ECDSA,
		Subject: pkix.Name{
			CommonName: "cert-manager-webhook-ca",
		},
		IsCA:      true,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(d.CADuration),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
	}
	// self sign the root CA
	_, cert, err = pki.SignCertificate(cert, cert, pk.Public(), pk)
	if err != nil {
		return err
	}
	certBytes, err := pki.EncodeX509(cert)
	if err != nil {
		return err
	}

	if s == nil {
		_, err := d.client.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      d.SecretName,
				Namespace: d.SecretNamespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "cert-manager",
				},
				Annotations: map[string]string{
					cmapi.AllowsInjectionFromSecretAnnotation: "true",
				},
			},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certBytes,
				corev1.TLSPrivateKeyKey: pkBytes,
				cmmeta.TLSCAKey:         certBytes,
			},
		}, metav1.CreateOptions{})
		if err != nil && apierrors.IsAlreadyExists(err) {
			// another controller has created the secret, we expect a watch event
			// to trigger another call to ensureCA
			d.log.V(logf.DebugLevel).Info("Failed to create new root CA Secret, another controller has created it, waiting for watch event")
			return nil
		}
		d.log.V(logf.InfoLevel).Info("Created new root CA Secret")
		return err
	}

	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}
	s.Data[corev1.TLSCertKey] = certBytes
	s.Data[corev1.TLSPrivateKeyKey] = pkBytes
	s.Data[cmmeta.TLSCAKey] = certBytes
	if _, err := d.client.Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		return err
	}
	d.log.V(logf.InfoLevel).Info("Updated existing root CA Secret")
	return nil
}

func (d *DynamicAuthority) handleAdd(obj interface{}) {
	ctx := context.Background()
	if err := d.ensureCA(ctx); err != nil {
		d.log.Error(err, "error ensuring CA")
	}
}

func (d *DynamicAuthority) handleUpdate(_, obj interface{}) {
	ctx := context.Background()
	if err := d.ensureCA(ctx); err != nil {
		d.log.Error(err, "error ensuring CA")
	}
}

func (d *DynamicAuthority) handleDelete(obj interface{}) {
	ctx := context.Background()
	if err := d.ensureCA(ctx); err != nil {
		d.log.Error(err, "error ensuring CA")
	}
}
