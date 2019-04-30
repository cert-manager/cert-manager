/*
Copyright 2018 The Kubernetes Authors.

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

package client

import (
	"context"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// ObjectKey identifies a Kubernetes Object.
type ObjectKey = types.NamespacedName

// ObjectKeyFromObject returns the ObjectKey given a runtime.Object
func ObjectKeyFromObject(obj runtime.Object) (ObjectKey, error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return ObjectKey{}, err
	}
	return ObjectKey{Namespace: accessor.GetNamespace(), Name: accessor.GetName()}, nil
}

// Patch is a patch that can be applied to a Kubernetes object.
type Patch interface {
	// Type is the PatchType of the patch.
	Type() types.PatchType
	// Data is the raw data representing the patch.
	Data(obj runtime.Object) ([]byte, error)
}

// TODO(directxman12): is there a sane way to deal with get/delete options?

// Reader knows how to read and list Kubernetes objects.
type Reader interface {
	// Get retrieves an obj for the given object key from the Kubernetes Cluster.
	// obj must be a struct pointer so that obj can be updated with the response
	// returned by the Server.
	Get(ctx context.Context, key ObjectKey, obj runtime.Object) error

	// List retrieves list of objects for a given namespace and list options. On a
	// successful call, Items field in the list will be populated with the
	// result returned from the server.
	List(ctx context.Context, list runtime.Object, opts ...ListOptionFunc) error
}

// Writer knows how to create, delete, and update Kubernetes objects.
type Writer interface {
	// Create saves the object obj in the Kubernetes cluster.
	Create(ctx context.Context, obj runtime.Object, opts ...CreateOptionFunc) error

	// Delete deletes the given obj from Kubernetes cluster.
	Delete(ctx context.Context, obj runtime.Object, opts ...DeleteOptionFunc) error

	// Update updates the given obj in the Kubernetes cluster. obj must be a
	// struct pointer so that obj can be updated with the content returned by the Server.
	Update(ctx context.Context, obj runtime.Object, opts ...UpdateOptionFunc) error

	// Patch patches the given obj in the Kubernetes cluster. obj must be a
	// struct pointer so that obj can be updated with the content returned by the Server.
	Patch(ctx context.Context, obj runtime.Object, patch Patch, opts ...PatchOptionFunc) error
}

// StatusClient knows how to create a client which can update status subresource
// for kubernetes objects.
type StatusClient interface {
	Status() StatusWriter
}

// StatusWriter knows how to update status subresource of a Kubernetes object.
type StatusWriter interface {
	// Update updates the fields corresponding to the status subresource for the
	// given obj. obj must be a struct pointer so that obj can be updated
	// with the content returned by the Server.
	Update(ctx context.Context, obj runtime.Object) error
}

// Client knows how to perform CRUD operations on Kubernetes objects.
type Client interface {
	Reader
	Writer
	StatusClient
}

// IndexerFunc knows how to take an object and turn it into a series
// of non-namespaced keys. Namespaced objects are automatically given
// namespaced and non-spaced variants, so keys do not need to include namespace.
type IndexerFunc func(runtime.Object) []string

// FieldIndexer knows how to index over a particular "field" such that it
// can later be used by a field selector.
type FieldIndexer interface {
	// IndexFields adds an index with the given field name on the given object type
	// by using the given function to extract the value for that field.  If you want
	// compatibility with the Kubernetes API server, only return one key, and only use
	// fields that the API server supports.  Otherwise, you can return multiple keys,
	// and "equality" in the field selector means that at least one key matches the value.
	// The FieldIndexer will automatically take care of indexing over namespace
	// and supporting efficient all-namespace queries.
	IndexField(obj runtime.Object, field string, extractValue IndexerFunc) error
}

// CreateOptions contains options for create requests. It's generally a subset
// of metav1.CreateOptions.
type CreateOptions struct {
	// When present, indicates that modifications should not be
	// persisted. An invalid or unrecognized dryRun directive will
	// result in an error response and no further processing of the
	// request. Valid values are:
	// - All: all dry run stages will be processed
	DryRun []string

	// Raw represents raw CreateOptions, as passed to the API server.
	Raw *metav1.CreateOptions
}

// AsCreateOptions returns these options as a metav1.CreateOptions.
// This may mutate the Raw field.
func (o *CreateOptions) AsCreateOptions() *metav1.CreateOptions {

	if o == nil {
		return &metav1.CreateOptions{}
	}
	if o.Raw == nil {
		o.Raw = &metav1.CreateOptions{}
	}

	o.Raw.DryRun = o.DryRun
	return o.Raw
}

// ApplyOptions executes the given CreateOptionFuncs and returns the mutated
// CreateOptions.
func (o *CreateOptions) ApplyOptions(optFuncs []CreateOptionFunc) *CreateOptions {
	for _, optFunc := range optFuncs {
		optFunc(o)
	}
	return o
}

// CreateOptionFunc is a function that mutates a CreateOptions struct. It implements
// the functional options pattern. See
// https://github.com/tmrts/go-patterns/blob/master/idiom/functional-options.md.
type CreateOptionFunc func(*CreateOptions)

// CreateDryRunAll is a functional option that sets the DryRun
// field of a CreateOptions struct to metav1.DryRunAll.
func CreateDryRunAll() CreateOptionFunc {
	return func(opts *CreateOptions) {
		opts.DryRun = []string{metav1.DryRunAll}
	}
}

// DeleteOptions contains options for delete requests. It's generally a subset
// of metav1.DeleteOptions.
type DeleteOptions struct {
	// GracePeriodSeconds is the duration in seconds before the object should be
	// deleted. Value must be non-negative integer. The value zero indicates
	// delete immediately. If this value is nil, the default grace period for the
	// specified type will be used.
	GracePeriodSeconds *int64

	// Preconditions must be fulfilled before a deletion is carried out. If not
	// possible, a 409 Conflict status will be returned.
	Preconditions *metav1.Preconditions

	// PropagationPolicy determined whether and how garbage collection will be
	// performed. Either this field or OrphanDependents may be set, but not both.
	// The default policy is decided by the existing finalizer set in the
	// metadata.finalizers and the resource-specific default policy.
	// Acceptable values are: 'Orphan' - orphan the dependents; 'Background' -
	// allow the garbage collector to delete the dependents in the background;
	// 'Foreground' - a cascading policy that deletes all dependents in the
	// foreground.
	PropagationPolicy *metav1.DeletionPropagation

	// Raw represents raw DeleteOptions, as passed to the API server.
	Raw *metav1.DeleteOptions
}

// AsDeleteOptions returns these options as a metav1.DeleteOptions.
// This may mutate the Raw field.
func (o *DeleteOptions) AsDeleteOptions() *metav1.DeleteOptions {

	if o == nil {
		return &metav1.DeleteOptions{}
	}
	if o.Raw == nil {
		o.Raw = &metav1.DeleteOptions{}
	}

	o.Raw.GracePeriodSeconds = o.GracePeriodSeconds
	o.Raw.Preconditions = o.Preconditions
	o.Raw.PropagationPolicy = o.PropagationPolicy
	return o.Raw
}

// ApplyOptions executes the given DeleteOptionFuncs and returns the mutated
// DeleteOptions.
func (o *DeleteOptions) ApplyOptions(optFuncs []DeleteOptionFunc) *DeleteOptions {
	for _, optFunc := range optFuncs {
		optFunc(o)
	}
	return o
}

// DeleteOptionFunc is a function that mutates a DeleteOptions struct. It implements
// the functional options pattern. See
// https://github.com/tmrts/go-patterns/blob/master/idiom/functional-options.md.
type DeleteOptionFunc func(*DeleteOptions)

// GracePeriodSeconds is a functional option that sets the GracePeriodSeconds
// field of a DeleteOptions struct.
func GracePeriodSeconds(gp int64) DeleteOptionFunc {
	return func(opts *DeleteOptions) {
		opts.GracePeriodSeconds = &gp
	}
}

// Preconditions is a functional option that sets the Preconditions field of a
// DeleteOptions struct.
func Preconditions(p *metav1.Preconditions) DeleteOptionFunc {
	return func(opts *DeleteOptions) {
		opts.Preconditions = p
	}
}

// PropagationPolicy is a functional option that sets the PropagationPolicy
// field of a DeleteOptions struct.
func PropagationPolicy(p metav1.DeletionPropagation) DeleteOptionFunc {
	return func(opts *DeleteOptions) {
		opts.PropagationPolicy = &p
	}
}

// ListOptions contains options for limiting or filtering results.
// It's generally a subset of metav1.ListOptions, with support for
// pre-parsed selectors (since generally, selectors will be executed
// against the cache).
type ListOptions struct {
	// LabelSelector filters results by label.  Use SetLabelSelector to
	// set from raw string form.
	LabelSelector labels.Selector
	// FieldSelector filters results by a particular field.  In order
	// to use this with cache-based implementations, restrict usage to
	// a single field-value pair that's been added to the indexers.
	FieldSelector fields.Selector

	// Namespace represents the namespace to list for, or empty for
	// non-namespaced objects, or to list across all namespaces.
	Namespace string

	// Raw represents raw ListOptions, as passed to the API server.  Note
	// that these may not be respected by all implementations of interface,
	// and the LabelSelector and FieldSelector fields are ignored.
	Raw *metav1.ListOptions
}

// SetLabelSelector sets this the label selector of these options
// from a string form of the selector.
func (o *ListOptions) SetLabelSelector(selRaw string) error {
	sel, err := labels.Parse(selRaw)
	if err != nil {
		return err
	}
	o.LabelSelector = sel
	return nil
}

// SetFieldSelector sets this the label selector of these options
// from a string form of the selector.
func (o *ListOptions) SetFieldSelector(selRaw string) error {
	sel, err := fields.ParseSelector(selRaw)
	if err != nil {
		return err
	}
	o.FieldSelector = sel
	return nil
}

// AsListOptions returns these options as a flattened metav1.ListOptions.
// This may mutate the Raw field.
func (o *ListOptions) AsListOptions() *metav1.ListOptions {
	if o == nil {
		return &metav1.ListOptions{}
	}
	if o.Raw == nil {
		o.Raw = &metav1.ListOptions{}
	}
	if o.LabelSelector != nil {
		o.Raw.LabelSelector = o.LabelSelector.String()
	}
	if o.FieldSelector != nil {
		o.Raw.FieldSelector = o.FieldSelector.String()
	}
	return o.Raw
}

// ApplyOptions executes the given ListOptionFuncs and returns the mutated
// ListOptions.
func (o *ListOptions) ApplyOptions(optFuncs []ListOptionFunc) *ListOptions {
	for _, optFunc := range optFuncs {
		optFunc(o)
	}
	return o
}

// ListOptionFunc is a function that mutates a ListOptions struct. It implements
// the functional options pattern. See
// https://github.com/tmrts/go-patterns/blob/master/idiom/functional-options.md.
type ListOptionFunc func(*ListOptions)

// MatchingLabels is a convenience function that sets the label selector
// to match the given labels, and then returns the options.
// It mutates the list options.
func (o *ListOptions) MatchingLabels(lbls map[string]string) *ListOptions {
	sel := labels.SelectorFromSet(lbls)
	o.LabelSelector = sel
	return o
}

// MatchingField is a convenience function that sets the field selector
// to match the given field, and then returns the options.
// It mutates the list options.
func (o *ListOptions) MatchingField(name, val string) *ListOptions {
	sel := fields.SelectorFromSet(fields.Set{name: val})
	o.FieldSelector = sel
	return o
}

// InNamespace is a convenience function that sets the namespace,
// and then returns the options. It mutates the list options.
func (o *ListOptions) InNamespace(ns string) *ListOptions {
	o.Namespace = ns
	return o
}

// MatchingLabels is a functional option that sets the LabelSelector field of
// a ListOptions struct.
func MatchingLabels(lbls map[string]string) ListOptionFunc {
	sel := labels.SelectorFromSet(lbls)
	return func(opts *ListOptions) {
		opts.LabelSelector = sel
	}
}

// MatchingField is a functional option that sets the FieldSelector field of
// a ListOptions struct.
func MatchingField(name, val string) ListOptionFunc {
	sel := fields.SelectorFromSet(fields.Set{name: val})
	return func(opts *ListOptions) {
		opts.FieldSelector = sel
	}
}

// InNamespace is a functional option that sets the Namespace field of
// a ListOptions struct.
func InNamespace(ns string) ListOptionFunc {
	return func(opts *ListOptions) {
		opts.Namespace = ns
	}
}

// UseListOptions is a functional option that replaces the fields of a
// ListOptions struct with those of a different ListOptions struct.
//
// Example:
// cl.List(ctx, list, client.UseListOptions(lo.InNamespace(ns).MatchingLabels(labels)))
func UseListOptions(newOpts *ListOptions) ListOptionFunc {
	return func(opts *ListOptions) {
		*opts = *newOpts
	}
}

// UpdateOptions contains options for create requests. It's generally a subset
// of metav1.UpdateOptions.
type UpdateOptions struct {
	// When present, indicates that modifications should not be
	// persisted. An invalid or unrecognized dryRun directive will
	// result in an error response and no further processing of the
	// request. Valid values are:
	// - All: all dry run stages will be processed
	DryRun []string

	// Raw represents raw UpdateOptions, as passed to the API server.
	Raw *metav1.UpdateOptions
}

// AsUpdateOptions returns these options as a metav1.UpdateOptions.
// This may mutate the Raw field.
func (o *UpdateOptions) AsUpdateOptions() *metav1.UpdateOptions {

	if o == nil {
		return &metav1.UpdateOptions{}
	}
	if o.Raw == nil {
		o.Raw = &metav1.UpdateOptions{}
	}

	o.Raw.DryRun = o.DryRun
	return o.Raw
}

// ApplyOptions executes the given UpdateOptionFuncs and returns the mutated
// UpdateOptions.
func (o *UpdateOptions) ApplyOptions(optFuncs []UpdateOptionFunc) *UpdateOptions {
	for _, optFunc := range optFuncs {
		optFunc(o)
	}
	return o
}

// UpdateOptionFunc is a function that mutates a UpdateOptions struct. It implements
// the functional options pattern. See
// https://github.com/tmrts/go-patterns/blob/master/idiom/functional-options.md.
type UpdateOptionFunc func(*UpdateOptions)

// UpdateDryRunAll is a functional option that sets the DryRun
// field of a UpdateOptions struct to metav1.DryRunAll.
func UpdateDryRunAll() UpdateOptionFunc {
	return func(opts *UpdateOptions) {
		opts.DryRun = []string{metav1.DryRunAll}
	}
}

// PatchOptions contains options for patch requests.
type PatchOptions struct {
	// When present, indicates that modifications should not be
	// persisted. An invalid or unrecognized dryRun directive will
	// result in an error response and no further processing of the
	// request. Valid values are:
	// - All: all dry run stages will be processed
	DryRun []string
	// Force is going to "force" Apply requests. It means user will
	// re-acquire conflicting fields owned by other people. Force
	// flag must be unset for non-apply patch requests.
	// +optional
	Force *bool

	// Raw represents raw PatchOptions, as passed to the API server.
	Raw *metav1.PatchOptions
}

// ApplyOptions executes the given PatchOptionFuncs, mutating these PatchOptions.
// It returns the mutated PatchOptions for convenience.
func (o *PatchOptions) ApplyOptions(optFuncs []PatchOptionFunc) *PatchOptions {
	for _, optFunc := range optFuncs {
		optFunc(o)
	}
	return o
}

// AsPatchOptions returns these options as a metav1.PatchOptions.
// This may mutate the Raw field.
func (o *PatchOptions) AsPatchOptions() *metav1.PatchOptions {
	if o == nil {
		return &metav1.PatchOptions{}
	}
	if o.Raw == nil {
		o.Raw = &metav1.PatchOptions{}
	}

	o.Raw.DryRun = o.DryRun
	o.Raw.Force = o.Force
	return o.Raw
}

// PatchOptionFunc is a function that mutates a PatchOptions struct. It implements
// the functional options pattern. See
// https://github.com/tmrts/go-patterns/blob/master/idiom/functional-options.md.
type PatchOptionFunc func(*PatchOptions)

// PatchDryRunAll is a functional option that sets the DryRun
// field of a PatchOptions struct to metav1.DryRunAll.
func PatchDryRunAll() PatchOptionFunc {
	return func(opts *PatchOptions) {
		opts.DryRun = []string{metav1.DryRunAll}
	}
}

// PatchWithForce is a functional option that sets the Force
// field of a PatchOptions struct to true.
func PatchWithForce() PatchOptionFunc {
	force := true
	return func(opts *PatchOptions) {
		opts.Force = &force
	}
}
