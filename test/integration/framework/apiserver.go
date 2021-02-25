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

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/versioning"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	webhooktesting "github.com/cert-manager/cert-manager/cmd/webhook/app/testing"
	"github.com/cert-manager/cert-manager/pkg/api"
	apitesting "github.com/cert-manager/cert-manager/pkg/api/testing"
)

func init() {
	// Set environment variables for controller-runtime's envtest package.
	// This is done once as we cannot scope environment variables to a single
	// invocation of RunControlPlane due to envtest's design.
	setUpEnvTestEnv()
}

type StopFunc func()

func RunControlPlane(t *testing.T) (*rest.Config, StopFunc) {
	webhookOpts, stopWebhook := webhooktesting.StartWebhookServer(t, []string{})
	crdsDir := apitesting.CRDDirectory(t)
	crds := readCustomResourcesAtPath(t, crdsDir)
	for _, crd := range crds {
		t.Logf("Found CRD with name %q", crd.Name)
	}
	patchCRDConversion(crds, webhookOpts.URL, webhookOpts.CAPEM)

	env := &envtest.Environment{
		AttachControlPlaneOutput: false,
		CRDs:                     crdsToRuntimeObjects(crds),
	}

	config, err := env.Start()
	if err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}

	cl, err := client.New(config, client.Options{Scheme: api.Scheme})
	if err != nil {
		t.Fatal(err)
	}

	// installing the validating webhooks, not using WebhookInstallOptions as it patches the CA to be it's own
	err = cl.Create(context.Background(), getValidatingWebhookConfig(webhookOpts.URL, webhookOpts.CAPEM))
	if err != nil {
		t.Fatal(err)
	}

	// installing the mutating webhooks, not using WebhookInstallOptions as it patches the CA to be it's own
	err = cl.Create(context.Background(), getMutatingWebhookConfig(webhookOpts.URL, webhookOpts.CAPEM))
	if err != nil {
		t.Fatal(err)
	}

	return config, func() {
		defer stopWebhook()
		if err := env.Stop(); err != nil {
			t.Logf("failed to shut down control plane, not failing test: %v", err)
		}
	}
}

var (
	internalScheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(metav1.AddMetaToScheme(internalScheme))
	apiextensionsinstall.Install(internalScheme)
}

func patchCRDConversion(crds []*v1.CustomResourceDefinition, url string, caPEM []byte) {
	for _, crd := range crds {
		if crd.Spec.Conversion == nil {
			continue
		}
		if crd.Spec.Conversion.Webhook == nil {
			continue
		}
		if crd.Spec.Conversion.Webhook.ClientConfig == nil {
			continue
		}
		if crd.Spec.Conversion.Webhook.ClientConfig.Service == nil {
			continue
		}
		path := ""
		if crd.Spec.Conversion.Webhook.ClientConfig.Service.Path != nil {
			path = *crd.Spec.Conversion.Webhook.ClientConfig.Service.Path
		}
		url := fmt.Sprintf("%s%s", url, path)
		crd.Spec.Conversion.Webhook.ClientConfig.URL = &url
		crd.Spec.Conversion.Webhook.ClientConfig.CABundle = caPEM
		crd.Spec.Conversion.Webhook.ClientConfig.Service = nil
	}
}

func readCustomResourcesAtPath(t *testing.T, path string) []*v1.CustomResourceDefinition {
	serializer := jsonserializer.NewSerializerWithOptions(jsonserializer.DefaultMetaFactory, internalScheme, internalScheme, jsonserializer.SerializerOptions{
		Yaml: true,
	})
	converter := runtime.UnsafeObjectConvertor(internalScheme)
	codec := versioning.NewCodec(serializer, serializer, converter, internalScheme, internalScheme, internalScheme, runtime.InternalGroupVersioner, runtime.InternalGroupVersioner, internalScheme.Name())

	var crds []*v1.CustomResourceDefinition
	if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}
		crd, err := readCRDsAtPath(codec, converter, path)
		if err != nil {
			return err
		}
		crds = append(crds, crd...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return crds
}

func readCRDsAtPath(codec runtime.Codec, converter runtime.ObjectConvertor, path string) ([]*v1.CustomResourceDefinition, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var crds []*v1.CustomResourceDefinition
	for _, d := range strings.Split(string(data), "\n---\n") {
		// skip empty YAML documents
		if strings.TrimSpace(d) == "" {
			continue
		}

		internalCRD := &apiextensions.CustomResourceDefinition{}
		if _, _, err := codec.Decode([]byte(d), nil, internalCRD); err != nil {
			return nil, err
		}

		out := &v1.CustomResourceDefinition{}
		if err := converter.Convert(internalCRD, out, nil); err != nil {
			return nil, err
		}

		crds = append(crds, out)
	}

	return crds, nil
}

func crdsToRuntimeObjects(in []*v1.CustomResourceDefinition) []runtime.Object {
	out := make([]runtime.Object, len(in))

	for i, crd := range in {
		out[i] = runtime.Object(crd)
	}

	return out
}

func getValidatingWebhookConfig(url string, caPEM []byte) runtime.Object {
	failurePolicy := admissionregistrationv1beta1.Fail
	sideEffects := admissionregistrationv1beta1.SideEffectClassNone
	validateURL := fmt.Sprintf("%s/validate", url)
	webhook := admissionregistrationv1beta1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cert-manager-webhook",
		},
		Webhooks: []admissionregistrationv1beta1.ValidatingWebhook{
			{
				Name: "webhook.cert-manager.io",
				ClientConfig: admissionregistrationv1beta1.WebhookClientConfig{
					URL:      &validateURL,
					CABundle: caPEM,
				},
				Rules: []admissionregistrationv1beta1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1beta1.OperationType{
							admissionregistrationv1beta1.Create,
							admissionregistrationv1beta1.Update,
						},
						Rule: admissionregistrationv1beta1.Rule{
							APIGroups:   []string{"cert-manager.io", "acme.cert-manager.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				},
				FailurePolicy: &failurePolicy,
				SideEffects:   &sideEffects,
			},
		},
	}

	return &webhook
}

func getMutatingWebhookConfig(url string, caPEM []byte) runtime.Object {
	failurePolicy := admissionregistrationv1beta1.Fail
	sideEffects := admissionregistrationv1beta1.SideEffectClassNone
	validateURL := fmt.Sprintf("%s/mutate", url)
	webhook := admissionregistrationv1beta1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cert-manager-webhook",
		},
		Webhooks: []admissionregistrationv1beta1.MutatingWebhook{
			{
				Name: "webhook.cert-manager.io",
				ClientConfig: admissionregistrationv1beta1.WebhookClientConfig{
					URL:      &validateURL,
					CABundle: caPEM,
				},
				Rules: []admissionregistrationv1beta1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1beta1.OperationType{
							admissionregistrationv1beta1.Create,
							admissionregistrationv1beta1.Update,
						},
						Rule: admissionregistrationv1beta1.Rule{
							APIGroups:   []string{"cert-manager.io", "acme.cert-manager.io"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				},
				FailurePolicy: &failurePolicy,
				SideEffects:   &sideEffects,
			},
		},
	}

	return &webhook
}
