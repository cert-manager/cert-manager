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

package migrateapiversion

import (
	"context"
	"fmt"
	"io"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Migrator struct {
	// Client used for API interactions
	Client client.Client

	// If true, skip checking the 'status.storedVersion' before running the migration.
	// By default, migration will only be run if the CRD contains storedVersions other
	// than the desired target version.
	SkipStoredVersionCheck bool

	// Writers to write informational & error messages to
	Out, ErrOut io.Writer
}

// NewMigrator creates a new migrator with the given API client.
// If either of out or errOut are nil, log messages will be discarded.
func NewMigrator(client client.Client, skipStoredVersionCheck bool, out, errOut io.Writer) *Migrator {
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}

	return &Migrator{
		Client:                 client,
		SkipStoredVersionCheck: skipStoredVersionCheck,
		Out:                    out,
		ErrOut:                 errOut,
	}
}

// Run begins the migration of all the named CRDs.
// It will attempt to migrate all resources defined as part of these CRDs to the
// given 'targetVersion', and after completion will update the `status.storedVersions`
// field on the corresponding CRD version to only contain the given targetVersion.
// Returns 'true' if a migration was actually performed, and false if migration was not required.
func (m *Migrator) Run(ctx context.Context, targetVersion string, names []string) (bool, error) {
	fmt.Fprintf(m.Out, "Checking all CustomResourceDefinitions have storage version set to \"%s\"\n", targetVersion)
	allTargetVersion, allCRDs, err := m.ensureCRDStorageVersionEquals(ctx, targetVersion, names)
	if err != nil {
		return false, err
	}
	if !allTargetVersion {
		fmt.Fprintf(m.ErrOut, "It looks like you are running a version of cert-manager that does not set the storage version of CRDs to %q. You MUST upgrade to cert-manager v1.0-v1.6 before migrating resources for v1.7.\n", targetVersion)
		return false, fmt.Errorf("preflight checks failed")
	}
	fmt.Fprintf(m.Out, "All CustomResourceDefinitions have %q configured as the storage version.\n", targetVersion)

	crdsRequiringMigration := allCRDs
	if !m.SkipStoredVersionCheck {
		fmt.Fprintf(m.Out, "Looking for CRDs that contain resources that require migrating to %q...\n", targetVersion)
		crdsRequiringMigration, err = m.discoverCRDsRequiringMigration(ctx, targetVersion, names)
		if err != nil {
			fmt.Fprintf(m.ErrOut, "Failed to determine resource types that require migration: %v\n", err)
			return false, err
		}
		if len(crdsRequiringMigration) == 0 {
			fmt.Fprintln(m.Out, "Nothing to do. cert-manager CRDs do not have \"status.storedVersions\" containing old API versions. You may proceed to upgrade to cert-manager v1.7.")
			return false, nil
		}
	} else {
		fmt.Fprintln(m.Out, "Forcing migration of all CRD resources as --skip-stored-version-check=true")
	}

	fmt.Fprintf(m.Out, "Found %d resource types that require migration:\n", len(crdsRequiringMigration))
	for _, crd := range crdsRequiringMigration {
		fmt.Fprintf(m.Out, " - %s (%s)\n", crd.Name, crd.Spec.Names.Kind)
	}

	for _, crd := range crdsRequiringMigration {
		if err := m.migrateResourcesForCRD(ctx, crd); err != nil {
			fmt.Fprintf(m.ErrOut, "Failed to migrate resource: %v\n", err)
			return false, err
		}
	}

	fmt.Fprintf(m.Out, "Patching CRD resources to set \"status.storedVersions\" to %q...\n", targetVersion)
	if err := m.patchCRDStoredVersions(ctx, crdsRequiringMigration); err != nil {
		fmt.Fprintf(m.ErrOut, "Failed to patch \"status.storedVersions\" field: %v\n", err)
		return false, err
	}

	fmt.Fprintln(m.Out, "Successfully migrated all cert-manager resource types. It is now safe to upgrade to cert-manager v1.7.")
	return true, nil
}

func (m *Migrator) ensureCRDStorageVersionEquals(ctx context.Context, vers string, names []string) (bool, []*apiext.CustomResourceDefinition, error) {
	var crds []*apiext.CustomResourceDefinition
	for _, crdName := range names {
		crd := &apiext.CustomResourceDefinition{}
		if err := m.Client.Get(ctx, client.ObjectKey{Name: crdName}, crd); err != nil {
			return false, nil, err
		}

		// Discover the storage version
		storageVersion := storageVersionForCRD(crd)

		if storageVersion != vers {
			fmt.Fprintf(m.Out, "CustomResourceDefinition object %q has storage version set to %q.\n", crdName, storageVersion)
			return false, nil, nil
		}

		crds = append(crds, crd)
	}

	return true, crds, nil
}

func (m *Migrator) discoverCRDsRequiringMigration(ctx context.Context, desiredStorageVersion string, names []string) ([]*apiext.CustomResourceDefinition, error) {
	var requireMigration []*apiext.CustomResourceDefinition
	for _, name := range names {
		crd := &apiext.CustomResourceDefinition{}
		if err := m.Client.Get(ctx, client.ObjectKey{Name: name}, crd); err != nil {
			return nil, err
		}
		// If no versions are stored, there's nothing to migrate.
		if len(crd.Status.StoredVersions) == 0 {
			continue
		}
		// If more than one entry exists in `storedVersions` OR if the only element in there is not
		// the desired version, perform a migration.
		if len(crd.Status.StoredVersions) > 1 || crd.Status.StoredVersions[0] != desiredStorageVersion {
			requireMigration = append(requireMigration, crd)
		}
	}
	return requireMigration, nil
}

func (m *Migrator) migrateResourcesForCRD(ctx context.Context, crd *apiext.CustomResourceDefinition) error {
	startTime := time.Now()
	timeFormat := "15:04:05"
	fmt.Fprintf(m.Out, "Migrating %q objects in group %q - this may take a while (started at %s)...\n", crd.Spec.Names.Kind, crd.Spec.Group, startTime.Format(timeFormat))
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   crd.Spec.Group,
		Version: storageVersionForCRD(crd),
		Kind:    crd.Spec.Names.ListKind,
	})
	if err := m.Client.List(ctx, list); err != nil {
		return err
	}
	fmt.Fprintf(m.Out, " %d resources to migrate...\n", len(list.Items))
	for _, obj := range list.Items {
		// retry on any kind of error to handle cases where e.g. the network connection to the apiserver fails
		if err := retry.OnError(wait.Backoff{
			Duration: time.Second, // wait 1s between attempts
			Steps:    3,           // allow up to 3 attempts per object
		}, func(err error) bool {
			// Retry on any errors that are not otherwise skipped/ignored
			return handleUpdateErr(err) != nil
		}, func() error { return m.Client.Update(ctx, &obj) }); handleUpdateErr(err) != nil {
			return err
		}
	}
	// add 500ms to the duration to ensure we always round up
	duration := time.Now().Sub(startTime) + (time.Millisecond * 500)
	fmt.Fprintf(m.Out, " Successfully migrated %d %s objects in %s\n", len(list.Items), crd.Spec.Names.Kind, duration.Round(time.Second))
	return nil
}

// patchCRDStoredVersions will patch the `status.storedVersions` field of all passed in CRDs to be
// set to an array containing JUST the current storage version.
// This is only safe to run after a successful migration (i.e. a read/write of all resources of the given CRD type).
func (m *Migrator) patchCRDStoredVersions(ctx context.Context, crds []*apiext.CustomResourceDefinition) error {
	for _, crd := range crds {
		// fetch a fresh copy of the CRD to avoid any conflict errors
		freshCRD := &apiext.CustomResourceDefinition{}
		if err := m.Client.Get(ctx, client.ObjectKey{Name: crd.Name}, freshCRD); err != nil {
			return err
		}

		// Check the latest copy of the CRD to ensure that:
		//   1) the storage version is the same as it was at the start of the migration
		//   2) the status.storedVersion field has not changed, and if it has, it has only added the new/desired storage version
		// This helps to avoid cases where the storage version was changed by a third-party midway through the migration,
		// which could lead to corrupted apiservers when we patch the status.storedVersions field below.
		expectedStorageVersion := storageVersionForCRD(crd)
		if storageVersionForCRD(freshCRD) != expectedStorageVersion {
			return newUnexpectedChangeError(crd)
		}
		newlyAddedVersions := storedVersionsAdded(crd, freshCRD)
		if newlyAddedVersions.Len() != 0 && !newlyAddedVersions.Equal(sets.NewString(expectedStorageVersion)) {
			return newUnexpectedChangeError(crd)
		}

		// Set the `status.storedVersions` field to the target storage version
		freshCRD.Status.StoredVersions = []string{storageVersionForCRD(crd)}

		if err := m.Client.Status().Update(ctx, freshCRD); err != nil {
			return err
		}
	}

	return nil
}

// storageVersionForCRD discovers the storage version for a given CRD.
func storageVersionForCRD(crd *apiext.CustomResourceDefinition) string {
	storageVersion := ""
	for _, v := range crd.Spec.Versions {
		if v.Storage {
			storageVersion = v.Name
			break
		}
	}
	return storageVersion
}

// storedVersionsAdded returns a list of any versions added to the `status.storedVersions` field on
// a CRD resource.
func storedVersionsAdded(old, new *apiext.CustomResourceDefinition) sets.String {
	oldStoredVersions := sets.NewString(old.Status.StoredVersions...)
	newStoredVersions := sets.NewString(new.Status.StoredVersions...)
	return newStoredVersions.Difference(oldStoredVersions)
}

// newUnexpectedChangeError creates a new 'error' that informs users that a change to the CRDs
// was detected during the migration process and so the migration must be re-run.
func newUnexpectedChangeError(crd *apiext.CustomResourceDefinition) error {
	errorFmt := "" +
		"The CRD %q unexpectedly changed during the migration. " +
		"This means that either an object was persisted in a non-storage version during the migration, " +
		"or the storage version was changed by someone else (or some automated deployment tooling) whilst the migration " +
		"was in progress.\n\n" +
		"All automated deployment tooling should be in a stable state (i.e. no upgrades to cert-manager CRDs should be" +
		"in progress whilst the migration is running).\n\n" +
		"Please ensure no changes to the CRDs are made during the migration process and re-run the migration until you" +
		"no longer see this message."
	return fmt.Errorf(errorFmt, crd.Name)
}

// handleUpdateErr will absorb certain types of errors that we know can be skipped/passed on
// during a migration of a particular object.
func handleUpdateErr(err error) error {
	if err == nil {
		return nil
	}
	// If the resource no longer exists, don't return the error as the object no longer
	// needs updating to the new API version.
	if apierrors.IsNotFound(err) {
		return nil
	}
	// If there was a conflict, another client must have written the object already which
	// means we don't need to force an update.
	if apierrors.IsConflict(err) {
		return nil
	}
	return err
}
