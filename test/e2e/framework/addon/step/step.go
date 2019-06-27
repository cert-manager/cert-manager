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

// package step contains an add-on that installs step certificates
package step

import (
	"fmt"
	"time"

	"github.com/jetstack/cert-manager/test/e2e/framework/addon/chart"
	"github.com/jetstack/cert-manager/test/e2e/framework/addon/tiller"
	"github.com/jetstack/cert-manager/test/e2e/framework/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// configuration used in /test/e2c/charts/step-certificates chart
	provisionerName     = "cert-manager"
	provisionerKid      = "Z2S-kUYeYrEdDN32RX0zjl1xY-XRtpxudC2hmplgK6U"
	provisionerPassword = "g9WY~0XW=\\)SpAm=_<{R4)<k;@Zo#.(o"
	caBundle            = `-----BEGIN CERTIFICATE-----
MIIBjDCCATKgAwIBAgIRAMFDGL1R3GzFunj9M/hH1iQwCgYIKoZIzj0EAwIwJDEi
MCAGA1UEAxMZQ2VydCBNYW5hZ2VyIFRlc3QgUm9vdCBDQTAeFw0xOTA2MjYxNjU2
MzlaFw0yOTA2MjMxNjU2MzlaMCQxIjAgBgNVBAMTGUNlcnQgTWFuYWdlciBUZXN0
IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATbqHQ+Gg6Yc5NZQ38q
NLuYfJklLLuvB2hnDch/b3imeQfEANCiXxOBtnOcAJuSP3sqxNGZXPj6EyJincAm
EEtTo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNV
HQ4EFgQU91VJlfkDfw0ziaWWfcxOBJGD7xQwCgYIKoZIzj0EAwIDSAAwRQIgZwrs
NSLM7V2PMU+bgSYkPfv7ATe5Los6RI1D+PZHriUCIQCLcgyWkG2h6J4etVHxp4RL
ZTJkx8uxINprKsNhwfjdWg==
-----END CERTIFICATE-----`
)

// Step describes the configuration details for an instance of step certificates
// deployed to the test cluster.
type Step struct {
	config        *config.Config
	chart         *chart.Chart
	tillerDetails *tiller.Details

	// Tiller is the tiller instance used to deploy the chart
	Tiller *tiller.Tiller

	// Name is a unique name for this step certificates deployment
	Name string

	// Namespace is the namespace to deploy step certificates into
	Namespace string

	details Details
}

type Details struct {
	// Kubectl is the path to kubectl
	Kubectl string

	// Host is the hostname that can be used to connect to step certificates
	Host string

	// PodName is the name of the step certificates pod
	PodName string

	// Namespace is the namespace step certificates has been deployed into
	Namespace string

	// ProvisionerName is the name of the provisioner.
	ProvisionerName string

	// ProvisionerKeyID is the kid of the provisioner.
	ProvisionerKeyID string

	// ProvisionerPasswordRef is the name of the secret that contains the
	// provisioner password.
	ProvisionerPasswordRef string

	// ProvisionerPasswordKey is the secret key that contains the provisioner
	// password.
	ProvisionerPasswordKey string

	// CABundle is the root certificate
	CABundle []byte
}

func (v *Step) Setup(cfg *config.Config) error {
	var err error
	if v.Name == "" {
		return fmt.Errorf("Name field must be set on the step add-on")
	}
	if v.Namespace == "" {
		return fmt.Errorf("Namespace field must be set on the step add-on")
	}
	if v.Tiller == nil {
		return fmt.Errorf("Tiller field must be set on the step add-on")
	}
	if cfg.Kubectl == "" {
		return fmt.Errorf("path to kubectl must be set")
	}
	v.details.Kubectl = cfg.Kubectl
	v.tillerDetails, err = v.Tiller.Details()
	if err != nil {
		return err
	}
	v.chart = &chart.Chart{
		Tiller:      v.Tiller,
		ReleaseName: "chart-step-" + v.Name,
		Namespace:   v.Namespace,
		ChartName:   cfg.RepoRoot + "/test/e2e/charts/step-certificates",
		// doesn't matter when installing from disk
		ChartVersion: "0.1.0",
		Vars:         []chart.StringTuple{},
	}
	err = v.chart.Setup(cfg)
	if err != nil {
		return err
	}
	return nil
}

// Provision will actually deploy this instance of Pebble-ingress to the cluster.
func (v *Step) Provision() error {
	err := v.chart.Provision()
	if err != nil {
		return err
	}

	// otherwise lookup the newly created pods name
	kubeClient := v.Tiller.Base.Details().KubeClient

	retries := 5
	for {
		pods, err := kubeClient.CoreV1().Pods(v.Namespace).List(metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=step-certificates",
		})
		if err != nil {
			return err
		}
		if len(pods.Items) == 0 {
			if retries == 0 {
				return fmt.Errorf("failed to create step-certificates pod within 10s")
			}
			retries--
			time.Sleep(time.Second * 2)
			continue
		}
		stepPod := pods.Items[0]
		// If the pod exists but is just waiting to be created, we allow it a
		// bit longer.
		if len(stepPod.Status.ContainerStatuses) == 0 || !stepPod.Status.ContainerStatuses[0].Ready {
			retries--
			time.Sleep(time.Second * 5)
			continue
		}
		v.details.PodName = stepPod.Name
		break
	}

	v.details.Namespace = v.Namespace
	v.details.Host = fmt.Sprintf("https://ca.%s.svc.cluster.local", v.Namespace)
	v.details.CABundle = []byte(caBundle)
	v.details.ProvisionerName = provisionerName
	v.details.ProvisionerKeyID = provisionerKid
	v.details.ProvisionerPasswordRef = "chart-step-" + v.Name + "-step-certificates-provisioner-password"
	v.details.ProvisionerPasswordKey = "password"

	return nil
}

// Details returns details that can be used to utilize the instance of step
// certificates.
func (v *Step) Details() *Details {
	return &v.details
}

// Deprovision will destroy this instance of step certificates.
func (v *Step) Deprovision() error {
	return v.chart.Deprovision()
}

func (v *Step) SupportsGlobal() bool {
	// We don't support global instances of step-certificates currently as we
	// need to generate PKI details at deploy time and make them available to
	// tests.
	return false
}

func (v *Step) Logs() (map[string]string, error) {
	return v.chart.Logs()
}
