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

package convert

import (
	"context"
	"fmt"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	logf "github.com/cert-manager/cert-manager/pkg/logs"

	"github.com/spf13/cobra"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apijson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/cli-runtime/pkg/resource"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/cert-manager/cert-manager/pkg/ctl"
)

var (
	example = templates.Examples(i18n.T(build.WithTemplate(`
		# Convert 'cert.yaml' to latest version and print to stdout.
		{{.BuildName}} convert -f cert.yaml

		# Convert kustomize overlay under current directory to 'cert-manager.io/v1alpha3'
		{{.BuildName}} convert -k . --output-version cert-manager.io/v1alpha3`)))

	longDesc = templates.LongDesc(i18n.T(`
Convert cert-manager config files between different API versions. Both YAML
and JSON formats are accepted.

The command takes filename, directory, or URL as input, and converts into the
format of the version specified by --output-version flag. If target version is
not specified or not supported, it will convert to the latest version

The default output will be printed to stdout in YAML format. One can use -o option
to change to output destination.`))
)

var (
	// Use this scheme as it has the internal cert-manager types
	// and their conversion functions registered.
	scheme = ctl.Scheme
)

// Options is a struct to support convert command
type Options struct {
	PrintFlags *genericclioptions.PrintFlags
	Printer    printers.ResourcePrinter

	OutputVersion string

	resource.FilenameOptions
	genericclioptions.IOStreams
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams:  ioStreams,
		PrintFlags: genericclioptions.NewPrintFlags("converted").WithDefaultOutput("yaml"),
	}
}

// NewCmdConvert returns a cobra command for converting cert-manager resources
func NewCmdConvert(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:                   "convert",
		Short:                 "Convert cert-manager config files between different API versions",
		Long:                  longDesc,
		Example:               example,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Complete())
			cmdutil.CheckErr(o.Run())
		},
	}

	cmd.Flags().StringVar(&o.OutputVersion, "output-version", o.OutputVersion, "Output the formatted object with the given group version (for ex: 'cert-manager.io/v1alpha3').")
	cmdutil.AddFilenameOptionFlags(cmd, &o.FilenameOptions, "Path to a file containing cert-manager resources to be converted.")
	o.PrintFlags.AddFlags(cmd)

	return cmd
}

// Complete collects information required to run Convert command from command line.
func (o *Options) Complete() error {
	err := o.FilenameOptions.RequireFilenameOrKustomize()
	if err != nil {
		return err
	}

	// build the printer
	o.Printer, err = o.PrintFlags.ToPrinter()
	if err != nil {
		return err
	}

	return nil
}

// Run executes convert command
func (o *Options) Run() error {
	builder := new(resource.Builder)

	r := builder.
		WithScheme(scheme).
		LocalParam(true).FilenameParam(false, &o.FilenameOptions).Flatten().Do()

	if err := r.Err(); err != nil {
		return err
	}

	singleItemImplied := false
	infos, err := r.IntoSingleItemImplied(&singleItemImplied).Infos()
	if err != nil {
		return err
	}

	if len(infos) == 0 {
		return fmt.Errorf("no objects passed to convert")
	}

	var specifiedOutputVersion schema.GroupVersion
	if len(o.OutputVersion) > 0 {
		specifiedOutputVersion, err = schema.ParseGroupVersion(o.OutputVersion)
		if err != nil {
			return err
		}
	}

	factory := serializer.NewCodecFactory(scheme)
	serializer := apijson.NewSerializerWithOptions(apijson.DefaultMetaFactory, scheme, scheme, apijson.SerializerOptions{})
	encoder := factory.WithoutConversion().EncoderForVersion(serializer, nil)
	objects, err := asVersionedObject(infos, !singleItemImplied, specifiedOutputVersion, encoder)
	if err != nil {
		return err
	}

	return o.Printer.PrintObj(objects, o.Out)
}

// asVersionedObject converts a list of infos into a single object - either a List containing
// the objects as children, or if only a single Object is present, as that object. The provided
// version will be preferred as the conversion target, but the Object's mapping version will be
// used if that version is not present.
func asVersionedObject(infos []*resource.Info, forceList bool, specifiedOutputVersion schema.GroupVersion, encoder runtime.Encoder) (runtime.Object, error) {
	objects, err := asVersionedObjects(infos, specifiedOutputVersion, encoder)
	if err != nil {
		return nil, err
	}

	var object runtime.Object
	if len(objects) == 1 && !forceList {
		object = objects[0]
	} else {
		object = &metainternalversion.List{Items: objects}

		targetVersions := []schema.GroupVersion{}
		if !specifiedOutputVersion.Empty() {
			targetVersions = append(targetVersions, specifiedOutputVersion)
		}
		// This is needed so we are able to handle the List object when converting
		// multiple resources
		targetVersions = append(targetVersions, schema.GroupVersion{Group: "", Version: "v1"})

		converted, err := tryConvert(object, targetVersions...)
		if err != nil {
			return nil, err
		}

		object = converted
	}

	actualVersion := object.GetObjectKind().GroupVersionKind()

	if actualVersion.Version != specifiedOutputVersion.Version {
		defaultVersionInfo := ""
		if len(actualVersion.Version) > 0 {
			defaultVersionInfo = fmt.Sprintf("Defaulting to %q", actualVersion.Version)
		}
		logf.V(logf.WarnLevel).Infof("info: the output version specified is invalid. %s\n", defaultVersionInfo)
	}

	return object, nil
}

// asVersionedObjects converts a list of infos into versioned objects. The provided
// version will be preferred as the conversion target, but the Object's mapping version will be
// used if that version is not present.
func asVersionedObjects(infos []*resource.Info, specifiedOutputVersion schema.GroupVersion, encoder runtime.Encoder) ([]runtime.Object, error) {
	objects := []runtime.Object{}
	for _, info := range infos {
		if info.Object == nil {
			continue
		}

		targetVersions := []schema.GroupVersion{}
		// objects that are not part of api.Scheme must be converted to JSON
		if !specifiedOutputVersion.Empty() {
			_, _, err := scheme.ObjectKinds(info.Object)
			if err != nil {
				if runtime.IsNotRegisteredError(err) {
					data, err := runtime.Encode(encoder, info.Object)
					if err != nil {
						return nil, err
					}
					objects = append(objects, &runtime.Unknown{Raw: data})
					continue
				}

				return nil, err
			}

			targetVersions = append(targetVersions, specifiedOutputVersion)
		} else {
			gvks, _, err := scheme.ObjectKinds(info.Object)
			if err == nil {
				for _, gvk := range gvks {
					targetVersions = append(targetVersions, scheme.PrioritizedVersionsForGroup(gvk.Group)...)
				}
			}
		}

		converted, err := tryConvert(info.Object, targetVersions...)
		if err != nil {
			return nil, err
		}
		objects = append(objects, converted)
	}

	return objects, nil
}

// tryConvert attempts to convert the given object to the provided versions in order. This function assumes
// the object is in internal version.
func tryConvert(object runtime.Object, versions ...schema.GroupVersion) (runtime.Object, error) {
	var last error
	for _, version := range versions {
		if version.Empty() {
			return object, nil
		}
		obj, err := scheme.ConvertToVersion(object, version)
		if err != nil {
			last = err
			continue
		}
		return obj, nil
	}

	return nil, last
}
