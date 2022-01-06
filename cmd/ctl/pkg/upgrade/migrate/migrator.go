package migrate

import (
	"context"
	"fmt"
	"io"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	Force bool

	// Writers to write informational & error messages to
	Out, ErrOut io.Writer
}

// NewMigrator creates a new migrator with the given API client.
// If either of out or errOut are nil, log messages will be discarded.
func NewMigrator(client client.Client, force bool, out, errOut io.Writer) *Migrator {
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}

	return &Migrator{
		Client: client,
		Force:  force,
		Out:    out,
		ErrOut: errOut,
	}
}

// Run begins the migration of all the named CRDs.
// It will attempt to migrate all resources defined as part of these CRDs to the
// given 'targetVersion', and after completion will update the `status.storedVersions`
// field on the corresponding CRD version to only contain the given targetVersion.
func (m *Migrator) Run(ctx context.Context, targetVersion string, names []string) error {
	fmt.Fprintf(m.Out, "Checking all CustomResourceDefinitions have storage version set to '%s'\n", targetVersion)
	allV1, allCRDs, err := m.ensureCRDStorageVersionEquals(ctx, targetVersion, names)
	if err != nil {
		return err
	}
	if !allV1 {
		fmt.Fprintln(m.ErrOut, "It looks like you are running a pre-1.0 version of cert-manager. Please upgrade cert-manager to v1.6 before upgrading to v1.7.")
		return fmt.Errorf("preflight checks failed")
	}
	fmt.Fprintf(m.Out, "All CustomResourceDefinitions have %q configured as the storage version.\n", targetVersion)

	crdsRequiringMigration := allCRDs
	if !m.Force {
		fmt.Fprintln(m.Out, "Looking for CRDs that contain resources that require migrating to 'v1'...")
		crdsRequiringMigration, err = m.discoverCRDsRequiringMigration(ctx, "v1", names)
		if err != nil {
			fmt.Fprintf(m.ErrOut, "Failed to determine resource types that require migration: %v\n", err)
			return err
		}
		if len(crdsRequiringMigration) == 0 {
			fmt.Fprintln(m.Out, "Nothing to do. cert-manager CRDs do not have 'status.storedVersions' containing old API versions. You may proceed to upgrade to cert-manager v1.7.")
			return nil
		}
	} else {
		fmt.Fprintln(m.Out, "Forcing migration of all CRD resources as --force=true")
	}

	fmt.Fprintf(m.Out, "Found %d resource types that require migration:\n", len(crdsRequiringMigration))
	for _, crd := range crdsRequiringMigration {
		fmt.Fprintf(m.Out, " - %s\n", crd.Name)
	}

	for _, crd := range crdsRequiringMigration {
		if err := m.migrateResourcesForCRD(ctx, crd); err != nil {
			fmt.Fprintf(m.ErrOut, "Failed to migrate resource: %v\n", err)
			return err
		}
	}

	fmt.Fprintf(m.Out, "Patching CRD resources to set 'status.storedVersions' to %q...\n", targetVersion)
	if err := m.patchCRDStoredVersions(ctx, crdsRequiringMigration); err != nil {
		fmt.Fprintf(m.ErrOut, "Failed to patch 'status.storedVersions' field: %v\n", err)
		return err
	}

	fmt.Fprintln(m.Out, "Successfully migrated all cert-manager resource types. It is now safe to proceed with upgrading to cert-manager v1.7.")
	return nil
}

func (m *Migrator) ensureCRDStorageVersionEquals(ctx context.Context, vers string, names []string) (bool, []*apiext.CustomResourceDefinition, error) {
	var crds []*apiext.CustomResourceDefinition
	for _, crdName := range names {
		crd := &apiext.CustomResourceDefinition{}
		if err := m.Client.Get(ctx, client.ObjectKey{Name: crdName}, crd); err != nil {
			return false, nil, err
		}

		// Discover the storage version
		storageVersion := ""
		for _, v := range crd.Spec.Versions {
			if v.Storage {
				storageVersion = v.Name
				break
			}
		}

		if storageVersion != vers {
			fmt.Fprintf(m.Out, "CustomResourceDefinition object %q has storage version set to %q. You MUST upgrade to cert-manager v1.0-v1.6 before migrating resources for v1.7.\n", crdName, storageVersion)
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
	fmt.Fprintf(m.Out, "Migrating %q objects in group %q - this may take a while (started at %s)...\n", crd.Spec.Names.Kind, crd.Spec.Group, startTime.Format(time.Stamp))
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   crd.Spec.Group,
		Version: "v1",
		Kind:    crd.Spec.Names.ListKind,
	})
	if err := m.Client.List(ctx, list); err != nil {
		return err
	}
	fmt.Fprintf(m.Out, " %d resources to migrate\n", len(list.Items))
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
	fmt.Fprintf(m.Out, " Successfully migrated %d %s objects in %s\n", len(list.Items), crd.Spec.Names.Kind, time.Now().Sub(startTime).Round(time.Second))
	return nil
}

func (m *Migrator) patchCRDStoredVersions(ctx context.Context, crds []*apiext.CustomResourceDefinition) error {
	for _, crd := range crds {
		// fetch a fresh copy of the CRD to avoid any conflict errors
		freshCRD := &apiext.CustomResourceDefinition{}
		if err := m.Client.Get(ctx, client.ObjectKey{Name: crd.Name}, freshCRD); err != nil {
			return err
		}

		// Set the `status.storedVersions` field to 'v1'
		freshCRD.Status.StoredVersions = []string{"v1"}

		if err := m.Client.Status().Update(ctx, freshCRD); err != nil {
			return err
		}
	}

	return nil
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
