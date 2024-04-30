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

package certificates

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	fakeclock "k8s.io/utils/clock/testing"

	"github.com/cert-manager/cert-manager/integration-tests/framework"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	controllerpkg "github.com/cert-manager/cert-manager/pkg/controller"
	controllermetrics "github.com/cert-manager/cert-manager/pkg/controller/certificates/metrics"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	"github.com/cert-manager/cert-manager/test/unit/gen"
)

var (
	fixedClock = fakeclock.NewFakeClock(time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC))

	clockCounterMetric = fmt.Sprintf(`# HELP certmanager_clock_time_seconds DEPRECATED: use clock_time_seconds_gauge instead. The clock time given in seconds (from 1970/01/01 UTC).
# TYPE certmanager_clock_time_seconds counter
certmanager_clock_time_seconds %.9e`, float64(fixedClock.Now().Unix()))
	clockGaugeMetric = fmt.Sprintf(`
# HELP certmanager_clock_time_seconds_gauge The clock time given in seconds (from 1970/01/01 UTC).
# TYPE certmanager_clock_time_seconds_gauge gauge
certmanager_clock_time_seconds_gauge %.9e`, float64(fixedClock.Now().Unix()))
)

// TestMetricscontoller performs a basic test to ensure that Certificates
// metrics are exposed when a Certificate is created, updated, and removed when
// it is deleted.
func TestMetricsController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*40)
	defer cancel()

	config, stopFn := framework.RunControlPlane(t, ctx)
	defer stopFn()

	// Build, instantiate and run the issuing controller.
	kubernetesCl, factory, cmClient, cmFactory, scheme := framework.NewClients(t, config)

	metricsHandler := metrics.New(logf.Log, fixedClock)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := metricsHandler.NewServer(ln)

	errCh := make(chan error)
	go func() {
		defer close(errCh)
		if err := server.Serve(ln); err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			t.Fatal(err)
		}
		err := <-errCh
		if err != nil {
			t.Fatal(err)
		}
	}()

	controllerContext := controllerpkg.Context{
		Scheme:                    scheme,
		KubeSharedInformerFactory: factory,
		SharedInformerFactory:     cmFactory,
		ContextOptions: controllerpkg.ContextOptions{
			Metrics: metricsHandler,
		},
	}
	ctrl, queue, mustSync := controllermetrics.NewController(&controllerContext)
	c := controllerpkg.NewController(
		"metrics_test",
		metricsHandler,
		ctrl.ProcessItem,
		mustSync,
		nil,
		queue,
	)
	stopController := framework.StartInformersAndController(t, factory, cmFactory, c)
	defer stopController()

	var (
		crtName         = "testcrt"
		namespace       = "testns"
		metricsEndpoint = fmt.Sprintf("http://%s/metrics", server.Addr)

		lastErr error
	)

	// Create Namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	_, err = kubernetesCl.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	testMetrics := func(expectedOutput string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsEndpoint, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		output, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if strings.TrimSpace(string(output)) != strings.TrimSpace(expectedOutput) {
			return fmt.Errorf("got unexpected metrics output\nexp:\n%s\ngot:\n%s\n",
				expectedOutput, output)
		}

		return nil
	}

	waitForMetrics := func(expectedOutput string) {
		err = wait.PollUntilContextCancel(ctx, time.Millisecond*100, true, func(ctx context.Context) (done bool, err error) {
			if err := testMetrics(expectedOutput); err != nil {
				lastErr = err
				return false, nil
			}

			return true, nil
		})
		if err != nil {
			t.Fatalf("%s: failed to wait for expected metrics to be exposed: %s", err, lastErr)
		}
	}

	// Should expose no additional metrics
	waitForMetrics(clockCounterMetric + clockGaugeMetric)

	// Create Certificate
	crt := gen.Certificate(crtName,
		gen.SetCertificateIssuer(cmmeta.ObjectReference{Kind: "Issuer", Name: "test-issuer", Group: "test-issuer-group"}),
		gen.SetCertificateSecretName(crtName),
		gen.SetCertificateCommonName(crtName),
		gen.SetCertificateNamespace(namespace),
		gen.SetCertificateUID("uid-1"),
	)

	crt, err = cmClient.CertmanagerV1().Certificates(namespace).Create(ctx, crt, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Should expose that Certificate as unknown with no expiry
	waitForMetrics(`# HELP certmanager_certificate_expiration_timestamp_seconds The date after which the certificate expires. Expressed as a Unix Epoch Time.
# TYPE certmanager_certificate_expiration_timestamp_seconds gauge
certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 0
# HELP certmanager_certificate_ready_status The ready status of the certificate.
# TYPE certmanager_certificate_ready_status gauge
certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 0
certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 0
certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 1
# HELP certmanager_certificate_renewal_timestamp_seconds The number of seconds before expiration time the certificate should renew.
# TYPE certmanager_certificate_renewal_timestamp_seconds gauge
certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 0
` + clockCounterMetric + clockGaugeMetric + `
# HELP certmanager_controller_sync_call_count The number of sync() calls made by a controller.
# TYPE certmanager_controller_sync_call_count counter
certmanager_controller_sync_call_count{controller="metrics_test"} 1
`)

	// Set Certificate Expiry and Ready status True
	crt.Status.NotAfter = &metav1.Time{
		Time: time.Unix(100, 0),
	}
	crt.Status.Conditions = []cmapi.CertificateCondition{
		{
			Type:   cmapi.CertificateConditionReady,
			Status: cmmeta.ConditionTrue,
		},
	}
	crt.Status.RenewalTime = &metav1.Time{
		Time: time.Unix(100, 0),
	}
	_, err = cmClient.CertmanagerV1().Certificates(namespace).UpdateStatus(ctx, crt, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Should expose that Certificate as ready with expiry
	waitForMetrics(`# HELP certmanager_certificate_expiration_timestamp_seconds The date after which the certificate expires. Expressed as a Unix Epoch Time.
# TYPE certmanager_certificate_expiration_timestamp_seconds gauge
certmanager_certificate_expiration_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 100
# HELP certmanager_certificate_ready_status The ready status of the certificate.
# TYPE certmanager_certificate_ready_status gauge
certmanager_certificate_ready_status{condition="False",issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 0
certmanager_certificate_ready_status{condition="True",issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 1
certmanager_certificate_ready_status{condition="Unknown",issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 0
# HELP certmanager_certificate_renewal_timestamp_seconds The number of seconds before expiration time the certificate should renew.
# TYPE certmanager_certificate_renewal_timestamp_seconds gauge
certmanager_certificate_renewal_timestamp_seconds{issuer_group="test-issuer-group",issuer_kind="Issuer",issuer_name="test-issuer",name="testcrt",namespace="testns"} 100
` + clockCounterMetric + clockGaugeMetric + `
# HELP certmanager_controller_sync_call_count The number of sync() calls made by a controller.
# TYPE certmanager_controller_sync_call_count counter
certmanager_controller_sync_call_count{controller="metrics_test"} 2
`)

	err = cmClient.CertmanagerV1().Certificates(namespace).Delete(ctx, crt.Name, metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Should expose no Certificates and only metrics sync count increase
	waitForMetrics(clockCounterMetric + clockGaugeMetric + `
# HELP certmanager_controller_sync_call_count The number of sync() calls made by a controller.
# TYPE certmanager_controller_sync_call_count counter
certmanager_controller_sync_call_count{controller="metrics_test"} 3
`)
}
