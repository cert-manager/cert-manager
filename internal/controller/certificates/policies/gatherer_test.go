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

	logtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	fakeclock "k8s.io/utils/clock/testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	testpkg "github.com/cert-manager/cert-manager/pkg/controller/test"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

func TestDataForCertificate(t *testing.T) {
	cr := func(crName, ownerCertUID string, annot map[string]string) *cmapi.CertificateRequest {
		return gen.CertificateRequest(crName, gen.SetCertificateRequestNamespace("ns-1"),
			gen.AddCertificateRequestOwnerReferences(gen.CertificateRef("some-cert-name-that-does-not-matter", ownerCertUID)),
			gen.AddCertificateRequestAnnotations(annot),
		)
	}

	tests := map[string]struct {
		builder    *testpkg.Builder
		givenCert  *cmapi.Certificate
		wantCurCR  *cmapi.CertificateRequest
		wantNextCR *cmapi.CertificateRequest
		wantSecret *corev1.Secret
		wantErr    string
	}{
		"when no secret is found, the returned secret is nil": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("default-unit-test-ns"),
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateUID("uid-1"),
			),
			builder:    &testpkg.Builder{},
			wantSecret: nil,
		},
		"when neither current nor next CRs exist, the returned cur and next CRs should be nil": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("default-unit-test-ns"),
				gen.SetCertificateSecretName("secret-1"),
				gen.SetCertificateUID("uid-1"),
			),
			builder:   &testpkg.Builder{},
			wantCurCR: nil,
		},
		"when cert revision=1 and no owned CRs, the returned cur and next CRs should be nil": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("ns-1"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
			),
			builder: &testpkg.Builder{CertManagerObjects: []runtime.Object{
				cr("cr-unknown-rev1", "unknown-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
				cr("cr-unknown-rev2", "unknown-uid", map[string]string{"cert-manager.io/certificate-revision": "2"}),
			}},
			wantCurCR:  nil,
			wantNextCR: nil,
		},
		"when cert revision=nil, should only return the next CR with revision=1": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("ns-1"),
				gen.SetCertificateUID("cert-1-uid"),
			),
			builder: &testpkg.Builder{CertManagerObjects: []runtime.Object{
				cr("cr-1-rev1", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
				cr("cr-1-rev2", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "2"}),

				// Edge cases.
				cr("cr-1-norev", "cert-1-uid", nil),
				cr("cr-1-empty", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": ""}),
				cr("cr-unrelated-rev1", "cert-unrelated-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
				cr("cr-unrelated-rev2", "cert-unrelated-uid", map[string]string{"cert-manager.io/certificate-revision": "2"}),
			}},
			wantCurCR:  nil,
			wantNextCR: cr("cr-1-rev1", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
		},
		"when cert revision=1, should return the current CR with revision=1 and the next CR with revision=2": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("ns-1"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
			),
			builder: &testpkg.Builder{CertManagerObjects: []runtime.Object{
				cr("cr-1-rev1", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
				cr("cr-1-rev2", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "2"}),
				cr("cr-1-rev3", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "3"}),

				// Edge cases.
				cr("cr-1-no-revision", "cert-1-uid", nil),
				cr("cr-1-empty", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": ""}),
				cr("cr-2-rev1", "cert-2-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
				cr("cr-unrelated-rev1", "cert-unrelated-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
				cr("cr-unrelated-rev2", "cert-unrelated-uid", map[string]string{"cert-manager.io/certificate-revision": "2"}),
				cr("cr-unrelated-rev3", "cert-unrelated-uid", map[string]string{"cert-manager.io/certificate-revision": "3"}),
			}},
			wantCurCR:  cr("cr-1-rev1", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
			wantNextCR: cr("cr-1-rev2", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "2"}),
		},
		"should error when duplicate current CRs are found": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("ns-1"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
			),
			builder: &testpkg.Builder{CertManagerObjects: []runtime.Object{
				cr("cr-1-rev1a", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
				cr("cr-1-rev1b", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "1"}),
			}},
			wantErr: `multiple CertificateRequests were found for the 'current' revision 1, issuance is skipped until there are no more duplicates`,
		},
		"should error when duplicate next CRs are found": {
			givenCert: gen.Certificate("cert-1", gen.SetCertificateNamespace("ns-1"),
				gen.SetCertificateUID("cert-1-uid"),
				gen.SetCertificateRevision(1),
			),
			builder: &testpkg.Builder{CertManagerObjects: []runtime.Object{
				cr("cr-1-rev2a", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "2"}),
				cr("cr-1-rev2b", "cert-1-uid", map[string]string{"cert-manager.io/certificate-revision": "2"}),
			}},
			wantErr: `multiple CertificateRequests were found for the 'next' revision 2, issuance is skipped until there are no more duplicates`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClockStart, _ := time.Parse(time.RFC3339, "2021-01-02T15:04:05Z07:00")
			log := logtesting.NewTestLogger(t)
			turnOnKlogIfVerboseTest()

			test.builder.T = t
			test.builder.Clock = fakeclock.NewFakeClock(fakeClockStart)

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
			noop := cache.ResourceEventHandlerFuncs{AddFunc: func(obj interface{}) {}}
			if _, err := test.builder.SharedInformerFactory.Certmanager().V1().CertificateRequests().Informer().AddEventHandler(noop); err != nil {
				t.Fatalf("failed to add event handler to CertificateRequest informer: %v", err)
			}
			if _, err := test.builder.KubeSharedInformerFactory.Secrets().Informer().AddEventHandler(noop); err != nil {
				t.Fatalf("failed to add event handler to Secret informer: %v", err)
			}

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
			// inconsistency, we do make sure to have the right input
			// argument being called.
			//
			// The problem with (2) is that not knowing if the call was
			// actually made or not prevents us from knowing whether the
			// input argument (i.e., the namespace) is checked or not.

			g := &Gatherer{
				CertificateRequestLister: test.builder.SharedInformerFactory.Certmanager().V1().CertificateRequests().Lister(),
				SecretLister:             test.builder.KubeSharedInformerFactory.Secrets().Lister(),
			}

			ctx := logf.NewContext(context.Background(), logf.WithResource(log, test.givenCert))
			got, gotErr := g.DataForCertificate(ctx, test.givenCert)

			if test.wantErr != "" {
				require.EqualError(t, gotErr, test.wantErr)
			} else {
				require.NoError(t, gotErr)

				assert.Equal(t, test.givenCert, got.Certificate, "input cert should always be equal to returned cert")
				assert.Equal(t, test.wantCurCR, got.CurrentRevisionRequest)
				assert.Equal(t, test.wantNextCR, got.NextRevisionRequest)
				assert.Equal(t, test.wantSecret, got.Secret)
			}
		})
	}
}

// The logs are helpful for debugging client-go-related issues (informer
// not starting...). This function passes the flag -v=4 to klog when the
// tests are being run with -v. Otherwise, the default klog level is used.
func turnOnKlogIfVerboseTest() {
	hasVerboseFlag := flag.Lookup("test.v").Value.String() == "true"
	if !hasVerboseFlag {
		return
	}

	klogFlags := flag.NewFlagSet("klog", flag.ExitOnError)
	klog.InitFlags(klogFlags)
	_ = klogFlags.Set("v", "4")
}
