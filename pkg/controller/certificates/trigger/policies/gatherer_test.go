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

package policies

import (
	"context"
	"flag"
	"testing"
	"time"

	logtest "github.com/jetstack/cert-manager/pkg/logs/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	fakeclock "k8s.io/utils/clock/testing"

	cmscheme "github.com/jetstack/cert-manager/pkg/api"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/jetstack/cert-manager/pkg/controller/test"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/test/unit/gen"
)

func TestDataForCertificate(t *testing.T) {
	tests := map[string]struct {
		builder     *testpkg.Builder
		givenCert   *cmapi.Certificate
		wantRequest *cmapi.CertificateRequest
		wantSecret  *corev1.Secret
		wantErr     string
	}{
		"should find the certificaterequest that matches revision and owner": {
			builder: &testpkg.Builder{
				KubeObjects: []runtime.Object{},
				CertManagerObjects: []runtime.Object{
					gen.CertificateRequest("cr-4", gen.SetCertificateRequestNamespace("default-unit-test-ns"),
						gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-4")),
						gen.AddCertificateRequestAnnotations(map[string]string{
							"cert-manager.io/certificate-revision": "4",
						}),
					),
					gen.CertificateRequest("cr-7", gen.SetCertificateRequestNamespace("default-unit-test-ns"),
						gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-7")),
						gen.AddCertificateRequestAnnotations(map[string]string{
							"cert-manager.io/certificate-revision": "7",
						}),
					),
					gen.CertificateRequest("cr-9", gen.SetCertificateRequestNamespace("default-unit-test-ns"),
						gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-9")),
					),
				},
				ExpectedEvents: []string{},
			},
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("default-unit-test-ns"),
				gen.SetCertificateUID("uid-7"),
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateRevision(7),
			),
			wantRequest: gen.CertificateRequest("cr-7", gen.SetCertificateRequestNamespace("default-unit-test-ns"),
				gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("cert-1", "uid-7")),
				gen.AddCertificateRequestAnnotations(map[string]string{
					"cert-manager.io/certificate-revision": "7",
				}),
			),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClockStart, _ := time.Parse(time.RFC3339, "2021-01-02T15:04:05Z07:00")
			log := logtest.TestLogger{T: t}
			turnOnKlogIfVerboseTest(t)

			test.builder.T = t
			test.builder.Clock = fakeclock.NewFakeClock(fakeClockStart)

			// In this test, we do not use Register(controller.Context).
			// The Register(controller.Context) usually takes care of
			// triggering the init() func in ./pkg/api/scheme.go. If we
			// forget to have the init() func called, the apiVersion and
			// kind fields on cert-manager objects are not automatically
			// filled, which breaks the lister cache (i.e., the "indexer").
			_ = cmscheme.Scheme

			test.builder.Init()

			// One weird behavior in client-go is that listers won't return
			// anything if no event handler has been registered on this
			// type's informer. This is because the "indexers" (i.e., the
			// client-go cache) being lazily created. In our case, the
			// indexer for the CR type only gets created if we register an
			// event handler on the CR informer. And since we do not use
			// the Register(controller.Context) in these lister-only unit
			// tests, we "force" the creation of the indexer for the CR
			// type by registering a fake handler.
			test.builder.SharedInformerFactory.Certmanager().V1().CertificateRequests().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {},
			})

			// Even though we are only relying on listers in this unit test
			// and do not use the informer event handlers, we still need to
			// start the informers since the listers would return nothing
			// otherwise (see above comment).
			test.builder.Start()

			defer test.builder.CheckAndFinish()

			// NOTE(mael): this unit test does not check whether or not the
			// lister function has been called with the right namespace.
			// Although the fake clientset does record the calls made
			// ("actions"), it only records the calls made to the client
			// itself and does not record actions for calls made to the
			// listers. For example, the following will be properly
			// recorded:
			//
			//    client.CertmanagerV1().CertificateRequests("ns").List
			//
			// On the contrary, the following example won't be recorded:
			//
			//    informer.Certmanager().V1().CertificateRequests().Lister().List
			//
			// Not being able to check the calls made to the lister causes
			// to issues: (1) we cannot check that the lister was called
			// using the right namespace, and (2) we cannot make sure that
			// the lister was actually called (or not called).
			//
			// The problem with (1) is that when the lister returns an
			// empty list, the empty list might be due to two different
			// causes: either the lister is called with an unexpected
			// namespace instead of the non-empty expected namespace, or
			// the lister is called with the right namespace and the fake
			// clientset behaved as expected. In order to avoid the
			// inconsistancy, we do make sure to have the right input
			// argument being called.
			//
			// The problem with (2) is that not knowing if the call was
			// actually made or not prevents us from knowing whether the
			// input argument (i.e., the namespace) is checked or not.

			g := &Gatherer{
				CertificateRequestLister: test.builder.SharedInformerFactory.Certmanager().V1().CertificateRequests().Lister(),
				SecretLister:             test.builder.KubeSharedInformerFactory.Core().V1().Secrets().Lister(),
			}

			ctx := logf.NewContext(context.Background(), logf.WithResource(log, test.givenCert))
			got, gotErr := g.DataForCertificate(ctx, test.givenCert)

			if test.wantErr != "" {
				require.EqualError(t, gotErr, test.wantErr)
			} else {
				require.NoError(t, gotErr)

				assert.Equal(t, test.givenCert, got.Certificate, "input cert should always be equal to returned cert")
				assert.Equal(t, test.wantRequest, got.CurrentRevisionRequest)
				assert.Equal(t, test.wantSecret, got.Secret)
			}
		})
	}
}

// The logs are helpful for debugging client-go-related issues (informer
// not starting...). This function passes the flag -v=4 to klog when the
// tests are being run with -v. Otherwise, the default klog level is used.
func turnOnKlogIfVerboseTest(t *testing.T) {
	hasVerboseFlag := flag.Lookup("test.v").Value.String() == "true"
	if !hasVerboseFlag {
		return
	}

	klogFlags := flag.NewFlagSet("klog", flag.ExitOnError)
	klog.InitFlags(klogFlags)
	_ = klogFlags.Set("v", "4")
}
