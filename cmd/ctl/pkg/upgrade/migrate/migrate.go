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
	"fmt"
	"time"

	"github.com/spf13/cobra"
	apiextinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/jetstack/cert-manager/cmd/ctl/pkg/build"
	"github.com/jetstack/cert-manager/cmd/ctl/pkg/factory"
	acmeinstall "github.com/jetstack/cert-manager/internal/apis/acme/install"
	cminstall "github.com/jetstack/cert-manager/internal/apis/certmanager/install"
)

var (
	long = templates.LongDesc(i18n.T(`
Ensures resources in your Kubernetes cluster are persisted in the v1 API version.

This must be run prior to upgrading to ensure your cluster is ready to upgrade to cert-manager v1.7 and beyond.

This command must be run with a cluster running cert-manager v1.0 or greater.`))

	example = templates.Examples(i18n.T(build.WithTemplate(`
# Check the cert-manager installation is ready to be upgraded to v1.7
{{.BuildName}} upgrade migrate
`)))
)

var scheme = runtime.NewScheme()

func init() {
	apiextinstall.Install(scheme)
	cminstall.Install(scheme)
	acmeinstall.Install(scheme)
}

// Options is a struct to support renew command
type Options struct {
	genericclioptions.IOStreams
	*factory.Factory

	client client.Client
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdMigrate returns a cobra command for updating resources in an apiserver
// to force a new storage version to be used.
func NewCmdMigrate(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)
	cmd := &cobra.Command{
		Use:     "migrate",
		Short:   "Migrate all existing persisted cert-manager resources to the v1 API version",
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(cmd, args))
			cmdutil.CheckErr(o.Complete())
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}

	o.Factory = factory.New(ctx, cmd)

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(cmd *cobra.Command, args []string) error {
	return nil
}

// Complete takes the command arguments and factory and infers any remaining options.
func (o *Options) Complete() error {
	var err error
	o.client, err = client.New(o.RESTConfig, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	return nil
}

// Run executes renew command
func (o *Options) Run(ctx context.Context, args []string) error {
	// Check all cert-manager CRDs to ensure that they have their
	// storage version set to v1.
	allCRDNames := []string{
		"certificates.cert-manager.io",
		"certificaterequests.cert-manager.io",
		"issuers.cert-manager.io",
		"clusterissuers.cert-manager.io",
		"orders.acme.cert-manager.io",
		"challenges.acme.cert-manager.io",
	}

	fmt.Fprintln(o.Out, "Checking all cert-manager CustomResourceDefinitions have storage version set to 'v1'")
	allV1, crdsRequiringMigration, err := o.ensureCRDStorageVersionEquals(ctx, "v1", allCRDNames)
	if err != nil {
		return err
	}
	if !allV1 {
		fmt.Fprintln(o.ErrOut, "It looks like you are running a pre-1.0 version of cert-manager. Please upgrade cert-manager to v1.6 before upgrading to v1.7.")
		return fmt.Errorf("migration failed")
	}
	fmt.Fprintln(o.Out, "All CustomResourceDefinitions have 'v1' configured as the storage version.")

	/*
		fmt.Fprintln(o.Out, "Looking for CRDs that contain resources that require migrating to 'v1'...")
		crdsRequiringMigration, err := o.discoverCRDsRequiringMigration(ctx, "v1", allCRDNames)
		if err != nil {
			fmt.Fprintf(o.ErrOut, "Failed to determine resource types that require migration: %v\n", err)
			return err
		}
		if len(crdsRequiringMigration) == 0 {
			fmt.Fprintln(o.Out, "Nothing to do. cert-manager CRDs do not have 'status.storedVersions' containing old API versions. You may proceed to upgrade to cert-manager v1.7.")
			return nil
		}
	*/

	fmt.Fprintf(o.Out, "Found %d resource types that require migration:\n", len(crdsRequiringMigration))
	for _, crd := range crdsRequiringMigration {
		fmt.Fprintf(o.Out, " - %s\n", crd.Name)
	}

	for _, crd := range crdsRequiringMigration {
		if err := o.migrateResourcesForCRD(ctx, crd); err != nil {
			fmt.Fprintf(o.ErrOut, "Failed to migrate resource: %v\n", err)
			return err
		}
	}

	fmt.Fprintln(o.Out, "Patching CRD resources to set 'status.storedVersions' to 'v1'...")
	if err := o.patchCRDStoredVersions(ctx, crdsRequiringMigration); err != nil {
		fmt.Fprintf(o.ErrOut, "Failed to patch 'status.storedVersions' field: %v\n", err)
		return err
	}

	fmt.Fprintln(o.Out, "Successfully migrated all cert-manager resource types. It is now safe to proceed with upgrading to cert-manager v1.7.")
	return nil
}

func (o *Options) ensureCRDStorageVersionEquals(ctx context.Context, vers string, names []string) (bool, []*apiext.CustomResourceDefinition, error) {
	var crds []*apiext.CustomResourceDefinition
	for _, crdName := range names {
		crd := &apiext.CustomResourceDefinition{}
		if err := o.client.Get(ctx, client.ObjectKey{Name: crdName}, crd); err != nil {
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
			fmt.Fprintf(o.Out, "CustomResourceDefinition object %q has storage version set to %q. You MUST upgrade to cert-manager v1.0-v1.6 before migrating resources for v1.7.\n", crdName, storageVersion)
			return false, nil, nil
		}

		crds = append(crds, crd)
	}

	return true, crds, nil
}

func (o *Options) discoverCRDsRequiringMigration(ctx context.Context, desiredStorageVersion string, names []string) ([]*apiext.CustomResourceDefinition, error) {
	var requireMigration []*apiext.CustomResourceDefinition
	for _, name := range names {
		crd := &apiext.CustomResourceDefinition{}
		if err := o.client.Get(ctx, client.ObjectKey{Name: name}, crd); err != nil {
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

func (o *Options) migrateResourcesForCRD(ctx context.Context, crd *apiext.CustomResourceDefinition) error {
	startTime := time.Now()
	fmt.Fprintf(o.Out, "Migrating %q objects in group %q - this may take a while (started at %s)...\n", crd.Spec.Names.Kind, crd.Spec.Group, startTime.Format(time.Stamp))
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   crd.Spec.Group,
		Version: "v1",
		Kind:    crd.Spec.Names.ListKind,
	})
	if err := o.client.List(ctx, list); err != nil {
		return err
	}
	fmt.Fprintf(o.Out, " %d resources to migrate\n", len(list.Items))
	for _, obj := range list.Items {
		if err := o.client.Update(ctx, &obj); handleUpdateErr(err) != nil {
			return err
		}
	}
	fmt.Fprintf(o.Out, " Successfully migrated %d %s objects in %s\n", len(list.Items), crd.Spec.Names.Kind, time.Now().Sub(startTime).Round(time.Second))
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

func (o *Options) patchCRDStoredVersions(ctx context.Context, crds []*apiext.CustomResourceDefinition) error {
	for _, crd := range crds {
		// fetch a fresh copy of the CRD to avoid any conflict errors
		freshCRD := &apiext.CustomResourceDefinition{}
		if err := o.client.Get(ctx, client.ObjectKey{Name: crd.Name}, freshCRD); err != nil {
			return err
		}

		// Set the `status.storedVersions` field to 'v1'
		freshCRD.Status.StoredVersions = []string{"v1"}

		if err := o.client.Status().Update(ctx, freshCRD); err != nil {
			return err
		}
	}

	return nil
}
