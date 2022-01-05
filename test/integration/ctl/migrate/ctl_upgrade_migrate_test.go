/*
Copyright 2022 The cert-manager Authors.

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

package migrate

import (
	"context"
	"os"
	"testing"
	"time"

	testlogger "github.com/go-logr/logr/testing"
	apiextinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/upgrade/migrate"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/install"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v1"
	"github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v2"
	"github.com/jetstack/cert-manager/test/integration/framework"
)

var (
	equivalentResources = map[string]client.Object{
		"v1": &v1.TestType{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "object",
				Namespace: "default",
			},
			TestField:          "abc",
			TestFieldImmutable: "def",
		},
		"v2": &v2.TestType{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "object",
				Namespace: "default",
			},
			TestField:          "abc",
			TestFieldImmutable: "def",
		},
	}
)

func newScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	apiextinstall.Install(scheme)
	install.Install(scheme)
	return scheme
}

func TestCtlUpgradeMigrate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	// Create the control plane with the TestType conversion handlers registered
	scheme := newScheme()
	// name of the testtype CRD resource
	crdName := "testtypes.testgroup.testing.cert-manager.io"
	restCfg, stop := framework.RunControlPlane(t, context.Background(),
		framework.WithCRDDirectory("../../../../pkg/webhook/handlers/testdata/apis/testgroup/crds"),
		framework.WithWebhookConversionHandler(handlers.NewSchemeBackedConverter(testlogger.TestLogger{T: t}, scheme)))
	defer stop()

	// Ensure the OpenAPI endpoint has been updated with the TestType CRD
	framework.WaitForOpenAPIResourcesToBeLoaded(t, ctx, restCfg, schema.GroupVersionKind{
		Group:   "testgroup.testing.cert-manager.io",
		Version: "v1",
		Kind:    "TestType",
	})

	// Create an API client
	cl, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	// Fetch a copy of the recently created TestType CRD
	crd := &apiext.CustomResourceDefinition{}
	if err := cl.Get(ctx, client.ObjectKey{Name: crdName}, crd); err != nil {
		t.Fatal(err)
	}

	// Identify the current storage version and one non-storage version for this CRD.
	// We'll be creating objects and then changing the storage version on the CRD to
	// the 'nonStorageVersion' and ensuring the migration/upgrade is successful.
	storageVersion, nonStorageVersion := versionsForCRD(crd)
	if storageVersion == "" || nonStorageVersion == "" {
		t.Fatal("this test requires testdata with both a storage and non-storage version set")
	}

	// Ensure the original storage version is the only one on the CRD
	if len(crd.Status.StoredVersions) != 1 || crd.Status.StoredVersions[0] != storageVersion {
		t.Errorf("Expected status.storedVersions to only contain the storage version %q but it was: %v", storageVersion, crd.Status.StoredVersions)
	}

	// Create a resource
	obj := equivalentResources[storageVersion]
	if err := cl.Create(ctx, obj); err != nil {
		t.Errorf("Failed to create test resource: %v", err)
	}

	// Set the storage version to the 'nonStorageVersion'
	setStorageVersion(crd, nonStorageVersion)
	if err := cl.Update(ctx, crd); err != nil {
		t.Fatalf("Failed to update CRD storage version: %v", err)
	}
	if len(crd.Status.StoredVersions) != 2 || crd.Status.StoredVersions[0] != storageVersion || crd.Status.StoredVersions[1] != nonStorageVersion {
		t.Fatalf("Expected status.storedVersions to contain [%s, %s] but it was: %v", storageVersion, nonStorageVersion, crd.Status.StoredVersions)
	}

	// Run the migrator and migrate all objects to the 'nonStorageVersion' (which is now the new storage version)
	migrator := migrate.NewMigrator(cl, false, os.Stdout, os.Stderr)
	if err := migrator.Run(ctx, nonStorageVersion, []string{crdName}); err != nil {
		t.Errorf("migrator failed to run: %v", err)
	}

	// Check the status.storedVersions field to ensure it only contains one element
	crd = &apiext.CustomResourceDefinition{}
	if err := cl.Get(ctx, client.ObjectKey{Name: crdName}, crd); err != nil {
		t.Fatal(err)
	}
	if len(crd.Status.StoredVersions) != 1 || crd.Status.StoredVersions[0] != nonStorageVersion {
		t.Fatalf("Expected status.storedVersions to be %q but it was: %v", nonStorageVersion, crd.Status.StoredVersions)
	}

	// Remove the previous storage version from the CRD and update it
	removeAPIVersion(crd, storageVersion)
	if err := cl.Update(ctx, crd); err != nil {
		t.Fatalf("Failed to remove old API version: %v", err)
	}

	// Attempt to read a resource list in the new API version
	objList := &unstructured.UnstructuredList{}
	objList.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   crd.Spec.Group,
		Version: nonStorageVersion,
		Kind:    crd.Spec.Names.ListKind,
	})
	if err := cl.List(ctx, objList); err != nil {
		t.Fatalf("Failed to list objects (gvk %v): %v", objList.GroupVersionKind(), err)
	}
	if len(objList.Items) != 1 {
		t.Fatalf("Expected a single TestType resource to exist")
	}
}

func versionsForCRD(crd *apiext.CustomResourceDefinition) (storage, nonstorage string) {
	storageVersion := ""
	nonStorageVersion := ""
	for _, v := range crd.Spec.Versions {
		if v.Storage {
			storageVersion = v.Name
		} else {
			nonStorageVersion = v.Name
		}
		if storageVersion != "" && nonStorageVersion != "" {
			break
		}
	}

	return storageVersion, nonStorageVersion
}

func setStorageVersion(crd *apiext.CustomResourceDefinition, newStorageVersion string) {
	for i, v := range crd.Spec.Versions {
		if v.Name == newStorageVersion {
			v.Storage = true
		} else if v.Storage {
			v.Storage = false
		}
		crd.Spec.Versions[i] = v
	}
}

func removeAPIVersion(crd *apiext.CustomResourceDefinition, version string) {
	var newVersions []apiext.CustomResourceDefinitionVersion
	for _, v := range crd.Spec.Versions {
		if v.Name != version {
			newVersions = append(newVersions, v)
		}
	}
	crd.Spec.Versions = newVersions
}
