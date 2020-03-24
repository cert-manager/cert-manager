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

package webhookbootstrap

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/scheduler"
	"github.com/jetstack/cert-manager/pkg/util"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// The webhook bootstrapper is responsible for managing the CA used
// by cert-manager's own CRD conversion/validation webhook.
// This is required because whilst the conversion webhook is unavailable, it is
// not guaranteed that certificate issuance can proceed so we have a 'bootstrap
// problem'.
// This controller relies on static configuration passed as arguments in order
// to issue certificates without interacting with cert-manager CRDs:
// - --webhook-ca-secret
// - --webhook-serving-secret
// - --webhook-dns-names
// - --webhook-namespace

type controller struct {
	webhookCASecret      string
	webhookServingSecret string
	webhookDNSNames      []string
	webhookNamespace     string

	scheduledWorkQueue scheduler.ScheduledWorkQueue
	secretLister       corelisters.SecretLister
	kubeClient         kubernetes.Interface
	clock              clock.Clock
	// certificateNeedsRenew is a function that can be used to determine whether
	// a certificate currently requires renewal.
	// This is a field on the controller struct to avoid having to maintain a reference
	// to the controller context, and to make it easier to fake out this call during tests.
	certificateNeedsRenew func(ctx context.Context, cert *x509.Certificate, crt *cmapi.Certificate) bool

	// defined as a field to make it easy to stub out for testing purposes
	generatePrivateKeyBytes generatePrivateKeyBytesFn
	signCertificate         signCertificateFunc
}

type signCertificateFunc func(crt *cmapi.Certificate, signeeKey, signerKey crypto.Signer, signerCert *x509.Certificate) ([]byte, error)

func signCertificateImpl(crt *cmapi.Certificate, signeeKey, signerKey crypto.Signer, signerCert *x509.Certificate) ([]byte, error) {
	cert, err := pki.GenerateTemplate(crt)
	if err != nil {
		return nil, err
	}
	if signerCert == nil {
		signerCert = cert
	}
	crtData, _, err := pki.SignCertificate(cert, signerCert, signeeKey.Public(), signerKey)
	if err != nil {
		return nil, err
	}
	return crtData, nil
}

// Register registers and constructs the controller using the provided context.
// It returns the workqueue to be used to enqueue items, a list of
// InformerSynced functions that must be synced, or an error.
func (c *controller) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, []controllerpkg.RunFunc, error) {
	// create a queue used to queue up items to be processed
	queue := workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(time.Second*5, time.Minute*30), ControllerName)

	// obtain references to all the informers used by this controller
	// don't use the SharedInformerFactory here as it is configured to watch
	// *all* namespaces, whereas we only want to watch the webhook bootstrap
	// namespace for secret resources.
	secretsInformer := coreinformers.NewSecretInformer(ctx.Client, ctx.WebhookBootstrapOptions.Namespace, time.Minute*5, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	// build a list of InformerSynced functions that will be returned by the Register method.
	// the controller will only begin processing items once all of these informers have synced.
	mustSync := []cache.InformerSynced{
		secretsInformer.HasSynced,
	}

	// set all the references to the listers for use by the Sync function
	c.secretLister = corelisters.NewSecretLister(secretsInformer.GetIndexer())

	// register handler functions
	secretsInformer.AddEventHandler(&controllerpkg.QueuingEventHandler{Queue: queue})

	c.kubeClient = ctx.Client

	// Create a scheduled work queue that calls the ctrl.queue.Add method for
	// each object in the queue. This is used to schedule re-checks of
	// Certificate resources when they get near to expiry
	c.scheduledWorkQueue = scheduler.NewScheduledWorkQueue(queue.Add)

	c.webhookDNSNames = ctx.WebhookBootstrapOptions.DNSNames
	c.webhookCASecret = ctx.WebhookBootstrapOptions.CASecretName
	c.webhookServingSecret = ctx.WebhookBootstrapOptions.ServingSecretName
	c.webhookNamespace = ctx.WebhookBootstrapOptions.Namespace
	c.certificateNeedsRenew = ctx.IssuerOptions.CertificateNeedsRenew
	c.generatePrivateKeyBytes = generatePrivateKeyBytesImpl
	c.signCertificate = signCertificateImpl
	c.clock = ctx.Clock

	return queue, mustSync, []controllerpkg.RunFunc{secretsInformer.Run}, nil
}

func (c *controller) ProcessItem(ctx context.Context, key string) error {
	ctx = logf.NewContext(ctx, nil, ControllerName)
	log := logf.FromContext(ctx)

	if len(c.webhookDNSNames) == 0 {
		log.Info("no webhook DNS names provided on start-up, not processing any resources.")
		return nil
	}

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		log.Error(err, "error parsing resource key in queue")
		return nil
	}

	if c.webhookNamespace != namespace || !(c.webhookCASecret == name || c.webhookServingSecret == name) {
		return nil
	}

	secret, err := c.secretLister.Secrets(namespace).Get(name)
	if apierrors.IsNotFound(err) {
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
		}
	} else if err != nil {
		return err
	}

	switch name {
	case c.webhookCASecret:
		return c.syncCASecret(ctx, secret)
	case c.webhookServingSecret:
		return c.syncServingSecret(ctx, secret)
	}

	return nil
}

func (c *controller) syncCASecret(ctx context.Context, secret *corev1.Secret) error {
	log := logf.FromContext(ctx, "ca-secret")
	log = logf.WithResource(log, secret)
	crt := buildCACertificate(secret)

	// read the existing private key
	pk, pkData, err := c.readSecretPrivateKey(log, secret, crt)
	if err != nil {
		return err
	}

	// read the existing certificate
	if !c.certificateRequiresIssuance(ctx, log, secret, pk, crt) {
		c.scheduleRenewal(log, secret)
		log.Info("ca certificate already up to date")
		return nil
	}

	signedCert, err := c.selfSignCertificate(crt, pk)
	if err != nil {
		log.Error(err, "error signing certificate")
		return err
	}

	return c.updateSecret(secret, pkData, signedCert, signedCert)
}

func (c *controller) syncServingSecret(ctx context.Context, secret *corev1.Secret) error {
	log := logf.FromContext(ctx, "ca-secret")
	log = logf.WithResource(log, secret)
	crt := buildServingCertificate(secret, c.webhookDNSNames)

	// first fetch the CA private key & certificate
	caSecret, err := c.secretLister.Secrets(c.webhookNamespace).Get(c.webhookCASecret)
	if apierrors.IsNotFound(err) {
		log.Error(err, "ca secret does not yet exist")
		// TODO: automatically sync the serving secret when the ca secret
		//       is updated and return nil here instead
		return err
	}
	if err != nil {
		return err
	}

	caPKData := readSecretDataKey(caSecret, corev1.TLSPrivateKeyKey)
	caPK, err := pki.DecodePrivateKeyBytes(caPKData)
	if err != nil {
		log.Error(err, "error decoding CA private key")
		return err
	}

	caCertData := readSecretDataKey(caSecret, corev1.TLSCertKey)
	caCert, err := pki.DecodeX509CertificateBytes(caCertData)
	if err != nil {
		log.Error(err, "error decoding CA certificate data")
		return err
	}

	// read the existing private key
	pk, pkData, err := c.readSecretPrivateKey(log, secret, crt)
	if err != nil {
		return err
	}

	if !c.certificateRequiresIssuance(ctx, log, secret, pk, crt) {
		c.scheduleRenewal(log, secret)
		log.Info("serving certificate already up to date")
		return nil
	}

	// TODO: check to make sure the serving certificate is signed by the CA
	certData, err := c.signCertificate(crt, pk, caPK, caCert)
	if err != nil {
		log.Error(err, "error signing certificate")
		return err
	}

	return c.updateSecret(secret, pkData, caCertData, certData)
}

func (c *controller) scheduleRenewal(log logr.Logger, s *corev1.Secret) {
	log = logf.WithResource(log, s)
	// read the existing certificate
	crtData := readSecretDataKey(s, corev1.TLSCertKey)
	if crtData == nil {
		log.Info("no certificate data found in secret")
		return
	}
	cert, err := pki.DecodeX509CertificateBytes(crtData)
	if err != nil {
		log.Error(err, "failed to decode certificate data in secret")
		return
	}
	key, err := controllerpkg.KeyFunc(s)
	if err != nil {
		log.Error(err, "internal error determining string key for secret")
		return
	}

	// renew 30d before expiry
	renewIn := cert.NotAfter.Add(-1 * time.Hour * 24 * 30).Sub(c.clock.Now())
	c.scheduledWorkQueue.Add(key, renewIn)
}

func (c *controller) certificateRequiresIssuance(ctx context.Context, log logr.Logger, secret *corev1.Secret, pk crypto.Signer, crt *cmapi.Certificate) bool {
	// read the existing certificate
	crtData := readSecretDataKey(secret, corev1.TLSCertKey)
	if crtData == nil {
		log.Info("issuing webhook certificate")
		return true
	}
	cert, err := pki.DecodeX509CertificateBytes(crtData)
	if err != nil {
		log.Info("re-issuing webhook certificate")
		return true
	}

	// ensure private key is valid for certificate
	matches, err := pki.PublicKeyMatchesCertificate(pk.Public(), cert)
	if err != nil {
		log.Error(err, "internal error checking certificate, re-issuing certificate")
		return true
	}
	if !matches {
		log.Info("certificate does not match private key, re-issuing")
		return true
	}

	// validate the common name is correct
	expectedCN := crt.Spec.CommonName
	gotCN := append(cert.DNSNames, cert.Subject.CommonName)
	if !util.Contains(gotCN, expectedCN) {
		log.Info("certificate common name is not as expected, re-issuing")
		return true
	}

	// validate the dns names are correct
	expectedDNSNames := crt.Spec.DNSNames
	if !util.Subset(cert.DNSNames, expectedDNSNames) {
		log.Info("certificate dns names are not as expected, re-issuing")
		return true
	}

	// validate the uri sans are correct
	expectedURINames := crt.Spec.URISANs
	if !util.EqualUnsorted(pki.URLsToString(cert.URIs), expectedURINames) {
		log.Info("certificate uri sans are not as expected, re-issuing")
		return true
	}

	// validate the ip addresses are correct
	if !util.EqualUnsorted(pki.IPAddressesToString(cert.IPAddresses), crt.Spec.IPAddresses) {
		log.Info("certificate ip addresses are not as expected, re-issuing")
		return true
	}

	// validate the email addressed are correct
	if !util.EqualUnsorted(cert.EmailAddresses, crt.Spec.EmailSANs) {
		log.Info("certificate email addresses are not as expected, re-issuing")
		return true
	}

	if c.certificateNeedsRenew(ctx, cert, crt) {
		log.Info("certificate requires renewal, re-issuing")
		return true
	}

	return false
}

func readSecretDataKey(secret *corev1.Secret, key string) []byte {
	if secret.Data == nil {
		return nil
	}
	d, ok := secret.Data[key]
	if !ok {
		return nil
	}
	return d
}

// readSecretPrivateKey will attempt to read the private key bytes from a
// secret and decode it into a Signer interface. If either fail then the key
// will be [re-]generated. We do not actually commit the key to the API server
// within the secret to prevent early mount attempts onto the webhook pod.
func (c *controller) readSecretPrivateKey(log logr.Logger, secret *corev1.Secret, crt *cmapi.Certificate) (crypto.Signer, []byte, error) {
	var err error

	pkData := readSecretDataKey(secret, corev1.TLSPrivateKeyKey)
	if pkData == nil {
		log.Info("generating new private key")

		pkData, err = c.generatePrivateKeyBytes(crt)
		if err != nil {
			return nil, nil, err
		}
	}

	pk, err := pki.DecodePrivateKeyBytes(pkData)
	if err != nil {
		log.Info("regenerating new private key due to failed decoding")

		// Here we are deleting the badly coded private key bytes from the Secret
		// and recursively calling this function again. This is a safe recursion
		// since in the next call, this index is always empty, and will be picked
		// up by the case above.
		delete(secret.Data, corev1.TLSPrivateKeyKey)
		return c.readSecretPrivateKey(log, secret, crt)
	}

	return pk, pkData, nil
}

func (c *controller) selfSignCertificate(crt *cmapi.Certificate, signeeKey crypto.Signer) ([]byte, error) {
	return c.signCertificate(crt, signeeKey, signeeKey, nil)
}

func (c *controller) updateSecret(secret *corev1.Secret, pk, ca, crt []byte) error {
	secret = secret.DeepCopy()
	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations[cmapi.AllowsInjectionFromSecretAnnotation] = "true"
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[corev1.TLSPrivateKeyKey] = pk
	secret.Data[corev1.TLSCertKey] = crt
	secret.Data[cmmeta.TLSCAKey] = ca
	secret.Type = corev1.SecretTypeTLS

	var err error
	if secret.ResourceVersion == "" {
		_, err = c.kubeClient.CoreV1().Secrets(secret.Namespace).Create(secret)
	} else {
		_, err = c.kubeClient.CoreV1().Secrets(secret.Namespace).Update(secret)
	}
	if err != nil {
		return err
	}

	return nil
}

// bootstrapSecrets will manually add the Webhook's CA and Serving Secrets onto
// the process queue. This is done since the Secrets have not been created yet.
// We could create empty Secrets here instead to trigger reconciles however,
// this causes issues whereby empty Secrets can delays in the webhook pod's
// start. See #2537
func (c *controller) bootstrapSecrets(ctx context.Context) {
	// TODO: we should be able to just not run the controller at all if these
	//       are not set, but for now we add this hacky check.
	if c.webhookNamespace == "" || c.webhookCASecret == "" || c.webhookServingSecret == "" {
		return
	}

	c.processMissingSecret(ctx, c.webhookCASecret)
	c.processMissingSecret(ctx, c.webhookServingSecret)
}

// processMissingSecret will push a secret onto the queue to be processed in 1
// second. This secret does not have to exist yet, since ProcessItem will
// create the Secret, should it not exist.
func (c *controller) processMissingSecret(ctx context.Context, name string) {
	ctx = logf.NewContext(ctx, nil, ControllerName)
	log := logf.FromContext(ctx)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: c.webhookNamespace,
		},
	}

	key, err := controllerpkg.KeyFunc(secret)
	if err != nil {
		log.Error(err, "internal error determining string key for secret")
		return
	}

	c.scheduledWorkQueue.Add(key, time.Second)
}

const (
	selfSignedIssuerName = "cert-manager-webhook-selfsigner"
	caIssuerName         = "cert-manager-webhook-ca"

	caKeyAlgorithm = cmapi.RSAKeyAlgorithm
	caKeySize      = 2048
	caKeyEncoding  = cmapi.PKCS1

	servingKeyAlgorithm = cmapi.RSAKeyAlgorithm
	servingKeySize      = 2048
	servingKeyEncoding  = cmapi.PKCS1
)

func buildCACertificate(secret *corev1.Secret) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            secret.Name,
			Namespace:       secret.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(secret, corev1.SchemeGroupVersion.WithKind("Secret"))},
		},
		Spec: cmapi.CertificateSpec{
			SecretName:   secret.Name,
			Organization: []string{"cert-manager.system"},
			CommonName:   "cert-manager.webhook.ca",
			// root CA is valid for 5 years as we don't currently handle
			// rotating the root properly
			Duration: &metav1.Duration{Duration: time.Hour * 24 * 365 * 5},
			IssuerRef: cmmeta.ObjectReference{
				Name: selfSignedIssuerName,
			},
			IsCA:         true,
			KeyAlgorithm: caKeyAlgorithm,
			KeySize:      caKeySize,
			KeyEncoding:  caKeyEncoding,
		},
	}
}

func buildServingCertificate(secret *corev1.Secret, dnsNames []string) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            secret.Name,
			Namespace:       secret.Namespace,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(secret, corev1.SchemeGroupVersion.WithKind("Secret"))},
		},
		Spec: cmapi.CertificateSpec{
			SecretName:   secret.Name,
			Organization: []string{"cert-manager.system"},
			DNSNames:     dnsNames,
			Duration:     &metav1.Duration{Duration: time.Hour * 24 * 365 * 1},
			IssuerRef: cmmeta.ObjectReference{
				Name: caIssuerName,
			},
			KeyAlgorithm: servingKeyAlgorithm,
			KeySize:      servingKeySize,
			KeyEncoding:  servingKeyEncoding,
		},
	}
}

type generatePrivateKeyBytesFn func(*cmapi.Certificate) ([]byte, error)

func generatePrivateKeyBytesImpl(crt *cmapi.Certificate) ([]byte, error) {
	signer, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return nil, err
	}

	keyData, err := pki.EncodePrivateKey(signer, crt.Spec.KeyEncoding)
	if err != nil {
		return nil, err
	}

	return keyData, nil
}

const (
	ControllerName = "webhook-bootstrap"
)

func init() {
	controllerpkg.Register(ControllerName, func(ctx *controllerpkg.Context) (controllerpkg.Interface, error) {
		ctrl := &controller{}
		return controllerpkg.NewBuilder(ctx, ControllerName).
			For(ctrl).
			First(ctrl.bootstrapSecrets).
			With(ctrl.bootstrapSecrets, time.Second*30).
			Complete()
	})
}
