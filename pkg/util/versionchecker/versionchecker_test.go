/*
Copyright 2021 The cert-manager Authors.

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

package versionchecker

import (
	"archive/tar"
	"context"
	"embed"
	"errors"
	"io"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/resource"
	kubernetesscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

//go:embed testdata/test_manifests.tar
var testFiles embed.FS

func loadManifests() (io.Reader, error, func() (string, error), func()) {
	data, err := testFiles.Open("testdata/test_manifests.tar")
	if err != nil {
		return nil, err, nil, nil
	}
	fileReader := tar.NewReader(data)

	return fileReader, nil, func() (string, error) {
			header, err := fileReader.Next()
			if err != nil {
				return "", err
			}
			return strings.TrimSuffix(header.Name, ".yaml"), nil
		}, func() {
			if err := data.Close(); err != nil {
				panic(err)
			}
		}
}

func manifestToObject(manifest io.Reader) ([]runtime.Object, error) {
	obj, err := resource.
		NewLocalBuilder().
		Flatten().
		Unstructured().
		Stream(manifest, "").
		Do().
		Object()
	if err != nil {
		return nil, err
	}

	list, ok := obj.(*corev1.List)
	if !ok {
		return nil, errors.New("Could not get list")
	}

	return transformObjects(list.Items)
}

func transformObjects(objects []runtime.RawExtension) ([]runtime.Object, error) {
	transformedObjects := []runtime.Object{}
	for _, resource := range objects {
		var err error
		gvk := resource.Object.GetObjectKind().GroupVersionKind()

		// Create a pod for a Deployment resource
		if gvk.Group == "apps" && gvk.Version == "v1" && gvk.Kind == "Deployment" {
			unstr := resource.Object.(*unstructured.Unstructured)

			var deployment appsv1.Deployment
			err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstr.Object, &deployment)
			if err != nil {
				return nil, err
			}

			pod, err := getPodFromTemplate(&deployment.Spec.Template, resource.Object, nil)
			if err != nil {
				return nil, err
			}

			transformedObjects = append(transformedObjects, pod)
		}

		transformedObjects = append(transformedObjects, resource.Object)
	}

	return transformedObjects, nil
}

func setupFakeVersionChecker(manifest io.Reader) (*versionChecker, error) {
	scheme := runtime.NewScheme()

	if err := kubernetesscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := apiextensionsv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	objs, err := manifestToObject(manifest)
	if err != nil {
		return nil, err
	}

	cl := fake.
		NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objs...).
		Build()

	return &versionChecker{
		client:         cl,
		versionSources: map[string]string{},
	}, nil
}

func TestVersionChecker(t *testing.T) {
	f, err, next, close := loadManifests()
	if err != nil {
		t.Fatal(err)
	}
	defer close()

	for {
		version, err := next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}

		t.Run(version, func(t *testing.T) {
			checker, err := setupFakeVersionChecker(f)
			if err != nil {
				t.Error(err)
			}

			versionGuess, err := checker.Version(context.TODO())
			if err != nil {
				t.Error(err)
			}

			if version != versionGuess.Detected {
				t.Fatalf("wrong -> expected: %s vs detected: %s", version, versionGuess)
			}
		})
	}
}
