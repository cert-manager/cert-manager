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

package framework

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	webhooktesting "github.com/cert-manager/cert-manager/cmd/webhook/app/testing"
	"github.com/cert-manager/cert-manager/internal/test/paths"
	"github.com/cert-manager/cert-manager/internal/webhook"
	"github.com/cert-manager/cert-manager/pkg/api"
	"github.com/cert-manager/cert-manager/pkg/webhook/handlers"
	"github.com/cert-manager/cert-manager/test/internal/apiserver"
)

type StopFunc func()

// controlPlaneOptions has parameters for the control plane of the integration
// test framework which can be overridden in tests.
type controlPlaneOptions struct {
	crdsDir                  *string
	webhookConversionHandler handlers.ConversionHook
}

type RunControlPlaneOption func(*controlPlaneOptions)

// WithCRDDirectory allows alternative CRDs to be loaded into the test API
// server in tests.
func WithCRDDirectory(directory string) RunControlPlaneOption {
	return func(o *controlPlaneOptions) {
		o.crdsDir = pointer.StringPtr(directory)
	}
}

// WithWebhookConversionHandler allows the webhook handler for the `/convert`
// endpoint to be overridden in tests.
func WithWebhookConversionHandler(handler handlers.ConversionHook) RunControlPlaneOption {
	return func(o *controlPlaneOptions) {
		o.webhookConversionHandler = handler
	}
}

func RunControlPlane(t *testing.T, ctx context.Context, optionFunctions ...RunControlPlaneOption) (*rest.Config, StopFunc) {
	crdDirectoryPath, err := paths.CRDDirectory()
	if err != nil {
		t.Fatal(err)
	}

	options := &controlPlaneOptions{
		crdsDir: pointer.StringPtr(crdDirectoryPath),
	}

	for _, f := range optionFunctions {
		f(options)
	}

	env, stopControlPlane := apiserver.RunBareControlPlane(t)
	testuser, err := env.ControlPlane.AddUser(envtest.User{Name: "test-user", Groups: []string{"cluster-admin"}}, env.Config)
	if err != nil {
		t.Fatal(err)
	}

	kubeconfig, err := testuser.KubeConfig()
	if err != nil {
		t.Fatal(err)
	}

	f, err := ioutil.TempFile("", "integration-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer func() {
		os.Remove(f.Name())
	}()
	if _, err := f.Write(kubeconfig); err != nil {
		t.Fatal(err)
	}

	webhookOpts, stopWebhook := webhooktesting.StartWebhookServer(
		t, ctx, []string{"--kubeconfig", f.Name()},
		webhook.WithConversionHandler(options.webhookConversionHandler),
	)

	crds := readCustomResourcesAtPath(t, *options.crdsDir)
	for _, crd := range crds {
		t.Logf("Found CRD with name %q", crd.Name)
	}
	patchCRDConversion(crds, webhookOpts.URL, webhookOpts.CAPEM)

	if _, err := envtest.InstallCRDs(env.Config, envtest.CRDInstallOptions{
		CRDs: crds,
	}); err != nil {
		t.Fatal(err)
	}

	cl, err := client.New(env.Config, client.Options{Scheme: api.Scheme})
	if err != nil {
		t.Fatal(err)
	}

	// installing the validating webhooks, not using WebhookInstallOptions as it patches the CA to be it's own
	err = cl.Create(ctx, getValidatingWebhookConfig(webhookOpts.URL, webhookOpts.CAPEM))
	if err != nil {
		t.Fatal(err)
	}

	// installing the mutating webhooks, not using WebhookInstallOptions as it patches the CA to be it's own
	err = cl.Create(ctx, getMutatingWebhookConfig(webhookOpts.URL, webhookOpts.CAPEM))
	if err != nil {
		t.Fatal(err)
	}

	return env.Config, func() {
		defer stopWebhook()
		stopControlPlane()
	}
}

var (
	internalScheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(metav1.AddMetaToScheme(internalScheme))
	apiextensionsinstall.Install(internalScheme)
}

// patchCRDConversion overrides the conversion configuration of the CRDs that
// are loaded in to the integration test API server,
// configuring the conversion to be handled by the local webhook server.
func patchCRDConversion(crds []*apiextensionsv1.CustomResourceDefinition, url string, caPEM []byte) {
	for i := range crds {
		url := fmt.Sprintf("%s%s", url, "/convert")
		crds[i].Spec.Conversion = &apiextensionsv1.CustomResourceConversion{
			Strategy: apiextensionsv1.WebhookConverter,
			Webhook: &apiextensionsv1.WebhookConversion{
				ClientConfig: &apiextensionsv1.WebhookClientConfig{
					URL:      &url,
					CABundle: caPEM,
				},
				ConversionReviewVersions: []string{"v1"},
			},
		}
	}
}

func readCustomResourcesAtPath(t *testing.T, path string) []*apiextensionsv1.CustomResourceDefinition {
	serializer := jsonserializer.NewSerializerWithOptions(jsonserializer.DefaultMetaFactory, internalScheme, internalScheme, jsonserializer.SerializerOptions{
		Yaml: true,
	})
	converter := runtime.UnsafeObjectConvertor(internalScheme)
	codec := versioning.NewCodec(serializer, serializer, converter, internalScheme, internalScheme, internalScheme, runtime.InternalGroupVersioner, runtime.InternalGroupVersioner, internalScheme.Name())

	var crds []*apiextensionsv1.CustomResourceDefinition
	if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}
		crd, err := readCRDsAtPath(codec, converter, path)
		if err != nil {
			return fmt.Errorf("failed reading CRDs at path %s: %w", path, err)
		}
		crds = append(crds, crd...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return crds
}

func readCRDsAtPath(codec runtime.Codec, converter runtime.ObjectConvertor, path string) ([]*apiextensionsv1.CustomResourceDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, d := range strings.Split(string(data), "\n---\n") {
		// skip empty YAML documents
		if strings.TrimSpace(d) == "" {
			continue
		}

		internalCRD := &apiextensions.CustomResourceDefinition{}
		if _, _, err := codec.Decode([]byte(d), nil, internalCRD); err != nil {
			return nil, err
		}

		out := apiextensionsv1.CustomResourceDefinition{}
		if err := converter.Convert(internalCRD, &out, nil); err != nil {
			return nil, err
		}

		crds = append(crds, &out)
	}

	return crds, nil
}

func getValidatingWebhookConfig(url string, caPEM []byte) client.Object {
	failurePolicy := admissionregistrationv1.Fail
	sideEffects := admissionregistrationv1.SideEffectClassNone
	validateURL := fmt.Sprintf("%s/validate", url)
	webhook := admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cert-manager-webhook",
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: "webhook.cert-manager.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					URL:      &validateURL,
					CABundle: caPEM,
				},
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"cert-manager.io", "acme.cert-manager.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	return &webhook
}

func getMutatingWebhookConfig(url string, caPEM []byte) client.Object {
	failurePolicy := admissionregistrationv1.Fail
	sideEffects := admissionregistrationv1.SideEffectClassNone
	validateURL := fmt.Sprintf("%s/mutate", url)
	webhook := admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cert-manager-webhook",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name: "webhook.cert-manager.io",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					URL:      &validateURL,
					CABundle: caPEM,
				},
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"cert-manager.io", "acme.cert-manager.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				},
				FailurePolicy:           &failurePolicy,
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}

	return &webhook
}
