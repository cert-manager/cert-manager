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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
)

// {{{ "Functional" Option Interfaces

// CreateOption is some configuration that modifies options for a create request.
type CreateOption interface {
	// ApplyToCreate applies this configuration to the given create options.
	ApplyToCreate(*CreateOptions)
}

// DeleteOption is some configuration that modifies options for a delete request.
type DeleteOption interface {
	// ApplyToDelete applies this configuration to the given delete options.
	ApplyToDelete(*DeleteOptions)
}

// ListOption is some configuration that modifies options for a list request.
type ListOption interface {
	// ApplyToList applies this configuration to the given list options.
	ApplyToList(*ListOptions)
}

// UpdateOption is some configuration that modifies options for a update request.
type UpdateOption interface {
	// ApplyToUpdate applies this configuration to the given update options.
	ApplyToUpdate(*UpdateOptions)
}

// PatchOption is some configuration that modifies options for a patch request.
type PatchOption interface {
	// ApplyToPatch applies this configuration to the given patch options.
	ApplyToPatch(*PatchOptions)
}

// DeleteAllOfOption is some configuration that modifies options for a delete request.
type DeleteAllOfOption interface {
	// ApplyToDeleteAllOf applies this configuration to the given deletecollection options.
	ApplyToDeleteAllOf(*DeleteAllOfOptions)
}

// }}}

// {{{ Multi-Type Options

// DryRunAll sets the "dry run" option to "all", executing all
// validation, etc without persisting the change to storage.
var DryRunAll = dryRunAll{}

type dryRunAll struct{}

func (dryRunAll) ApplyToCreate(opts *CreateOptions) {
	opts.DryRun = []string{metav1.DryRunAll}
}
func (dryRunAll) ApplyToUpdate(opts *UpdateOptions) {
	opts.DryRun = []string{metav1.DryRunAll}
}
func (dryRunAll) ApplyToPatch(opts *PatchOptions) {
	opts.DryRun = []string{metav1.DryRunAll}
}
func (dryRunAll) ApplyToDelete(opts *DeleteOptions) {
	opts.DryRun = []string{metav1.DryRunAll}
}

// FieldOwner set the field manager name for the given server-side apply patch.
type FieldOwner string

func (f FieldOwner) ApplyToPatch(opts *PatchOptions) {
	opts.FieldManager = string(f)
}
func (f FieldOwner) ApplyToCreate(opts *CreateOptions) {
	opts.FieldManager = string(f)
}
func (f FieldOwner) ApplyToUpdate(opts *UpdateOptions) {
	opts.FieldManager = string(f)
}

// }}}

// {{{ Create Options

// CreateOptions contains options for create requests. It's generally a subset
// of metav1.CreateOptions.
type CreateOptions struct {
	// When present, indicates that modifications should not be
	// persisted. An invalid or unrecognized dryRun directive will
	// result in an error response and no further processing of the
	// request. Valid values are:
	// - All: all dry run stages will be processed
	DryRun []string

	// FieldManager is the name of the user or component submitting
	// this request.  It must be set with server-side apply.
	FieldManager string

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
	o.Raw.FieldManager = o.FieldManager
	return o.Raw
}

// ApplyOptions applies the given create options on these options,
// and then returns itself (for convenient chaining).
func (o *CreateOptions) ApplyOptions(opts []CreateOption) *CreateOptions {
	for _, opt := range opts {
		opt.ApplyToCreate(o)
	}
	return o
}

// CreateDryRunAll sets the "dry run" option to "all".
//
// Deprecated: Use DryRunAll
var CreateDryRunAll = DryRunAll

// }}}

// {{{ Delete Options

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

	// When present, indicates that modifications should not be
	// persisted. An invalid or unrecognized dryRun directive will
	// result in an error response and no further processing of the
	// request. Valid values are:
	// - All: all dry run stages will be processed
	DryRun []string
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
	o.Raw.DryRun = o.DryRun
	return o.Raw
}

// ApplyOptions applies the given delete options on these options,
// and then returns itself (for convenient chaining).
func (o *DeleteOptions) ApplyOptions(opts []DeleteOption) *DeleteOptions {
	for _, opt := range opts {
		opt.ApplyToDelete(o)
	}
	return o
}

// GracePeriodSeconds sets the grace period for the deletion
// to the given number of seconds.
type GracePeriodSeconds int64

func (s GracePeriodSeconds) ApplyToDelete(opts *DeleteOptions) {
	secs := int64(s)
	opts.GracePeriodSeconds = &secs
}

func (s GracePeriodSeconds) ApplyToDeleteAllOf(opts *DeleteAllOfOptions) {
	s.ApplyToDelete(&opts.DeleteOptions)
}

type Preconditions metav1.Preconditions

func (p Preconditions) ApplyToDelete(opts *DeleteOptions) {
	preconds := metav1.Preconditions(p)
	opts.Preconditions = &preconds
}

func (p Preconditions) ApplyToDeleteAllOf(opts *DeleteAllOfOptions) {
	p.ApplyToDelete(&opts.DeleteOptions)
}

type PropagationPolicy metav1.DeletionPropagation

func (p PropagationPolicy) ApplyToDelete(opts *DeleteOptions) {
	policy := metav1.DeletionPropagation(p)
	opts.PropagationPolicy = &policy
}

func (p PropagationPolicy) ApplyToDeleteAllOf(opts *DeleteAllOfOptions) {
	p.ApplyToDelete(&opts.DeleteOptions)
}

// }}}

// {{{ List Options

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

// ApplyOptions applies the given list options on these options,
// and then returns itself (for convenient chaining).
func (o *ListOptions) ApplyOptions(opts []ListOption) *ListOptions {
	for _, opt := range opts {
		opt.ApplyToList(o)
	}
	return o
}

// MatchingLabels filters the list/delete operation on the given set of labels.
type MatchingLabels map[string]string

func (m MatchingLabels) ApplyToList(opts *ListOptions) {
	// TODO(directxman12): can we avoid reserializing this over and over?
	sel := labels.SelectorFromSet(map[string]string(m))
	opts.LabelSelector = sel
}

func (m MatchingLabels) ApplyToDeleteAllOf(opts *DeleteAllOfOptions) {
	m.ApplyToList(&opts.ListOptions)
}

// MatchingField filters the list operation on the given field selector
// (or index in the case of cached lists).
//
// Deprecated: Use MatchingFields
func MatchingField(name, val string) MatchingFields {
	return MatchingFields{name: val}
}

// MatchingField filters the list/delete operation on the given field selector
// (or index in the case of cached lists).
type MatchingFields fields.Set

func (m MatchingFields) ApplyToList(opts *ListOptions) {
	// TODO(directxman12): can we avoid re-serializing this?
	sel := fields.SelectorFromSet(fields.Set(m))
	opts.FieldSelector = sel
}

func (m MatchingFields) ApplyToDeleteAllOf(opts *DeleteAllOfOptions) {
	m.ApplyToList(&opts.ListOptions)
}

// InNamespace restricts the list/delete operation to the given namespace.
type InNamespace string

func (n InNamespace) ApplyToList(opts *ListOptions) {
	opts.Namespace = string(n)
}

func (n InNamespace) ApplyToDeleteAllOf(opts *DeleteAllOfOptions) {
	n.ApplyToList(&opts.ListOptions)
}

// }}}

// {{{ Update Options

// UpdateOptions contains options for create requests. It's generally a subset
// of metav1.UpdateOptions.
type UpdateOptions struct {
	// When present, indicates that modifications should not be
	// persisted. An invalid or unrecognized dryRun directive will
	// result in an error response and no further processing of the
	// request. Valid values are:
	// - All: all dry run stages will be processed
	DryRun []string

	// FieldManager is the name of the user or component submitting
	// this request.  It must be set with server-side apply.
	FieldManager string

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
	o.Raw.FieldManager = o.FieldManager
	return o.Raw
}

// ApplyOptions applies the given update options on these options,
// and then returns itself (for convenient chaining).
func (o *UpdateOptions) ApplyOptions(opts []UpdateOption) *UpdateOptions {
	for _, opt := range opts {
		opt.ApplyToUpdate(o)
	}
	return o
}

// UpdateDryRunAll sets the "dry run" option to "all".
//
// Deprecated: Use DryRunAll
var UpdateDryRunAll = DryRunAll

// }}}

// {{{ Patch Options

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

	// FieldManager is the name of the user or component submitting
	// this request.  It must be set with server-side apply.
	FieldManager string

	// Raw represents raw PatchOptions, as passed to the API server.
	Raw *metav1.PatchOptions
}

// ApplyOptions applies the given patch options on these options,
// and then returns itself (for convenient chaining).
func (o *PatchOptions) ApplyOptions(opts []PatchOption) *PatchOptions {
	for _, opt := range opts {
		opt.ApplyToPatch(o)
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
	o.Raw.FieldManager = o.FieldManager
	return o.Raw
}

// ForceOwnership indicates that in case of conflicts with server-side apply,
// the client should acquire ownership of the conflicting field.  Most
// controllers should use this.
var ForceOwnership = forceOwnership{}

type forceOwnership struct{}

func (forceOwnership) ApplyToPatch(opts *PatchOptions) {
	definitelyTrue := true
	opts.Force = &definitelyTrue
}

// PatchDryRunAll sets the "dry run" option to "all".
//
// Deprecated: Use DryRunAll
var PatchDryRunAll = DryRunAll

// }}}

// {{{ DeleteAllOf Options

// these are all just delete options and list options

// DeleteAllOfOptions contains options for deletecollection (deleteallof) requests.
// It's just list and delete options smooshed together.
type DeleteAllOfOptions struct {
	ListOptions
	DeleteOptions
}

// ApplyOptions applies the given deleteallof options on these options,
// and then returns itself (for convenient chaining).
func (o *DeleteAllOfOptions) ApplyOptions(opts []DeleteAllOfOption) *DeleteAllOfOptions {
	for _, opt := range opts {
		opt.ApplyToDeleteAllOf(o)
	}
	return o
}

// }}}
