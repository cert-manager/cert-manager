/*
Copyright 2019 The Kubernetes Authors.

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

// Package rbac contain libraries for generating RBAC manifests from RBAC
// markers in Go source files.
//
// The markers take the form:
//
//  +kubebuilder:rbac:groups=<groups>,resources=<resources>,verbs=<verbs>,urls=<non resource urls>
package rbac

import (
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-tools/pkg/genall"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

var (
	// RuleDefinition is a marker for defining RBAC rules.
	// Call ToRule on the value to get a Kubernetes RBAC policy rule.
	RuleDefinition = markers.Must(markers.MakeDefinition("kubebuilder:rbac", markers.DescribesPackage, Rule{}))
)

// +controllertools:marker:generateHelp:category=RBAC

// Rule specifies an RBAC rule to all access to some resources or non-resource URLs.
type Rule struct {
	// Groups specifies the API groups that this rule encompasses.
	Groups []string `marker:",optional"`
	// Resources specifies the API resources that this rule encompasses.
	Resources []string `marker:",optional"`
	// Verbs specifies the (lowercase) kubernetes API verbs that this rule encompasses.
	Verbs []string
	// URL specifies the non-resource URLs that this rule encompasses.
	URLs []string `marker:"urls,optional"`
}

// ruleKey represents the resources and non-resources a Rule applies.
type ruleKey struct {
	Groups    string
	Resources string
	URLs      string
}

func (key ruleKey) String() string {
	return fmt.Sprintf("%s + %s + %s", key.Groups, key.Resources, key.URLs)
}

// ruleKeys implements sort.Interface
type ruleKeys []ruleKey

func (keys ruleKeys) Len() int           { return len(keys) }
func (keys ruleKeys) Swap(i, j int)      { keys[i], keys[j] = keys[j], keys[i] }
func (keys ruleKeys) Less(i, j int) bool { return keys[i].String() < keys[j].String() }

// key normalizes the Rule and returns a ruleKey object.
func (r *Rule) key() ruleKey {
	r.normalize()
	return ruleKey{
		Groups:    strings.Join(r.Groups, "&"),
		Resources: strings.Join(r.Resources, "&"),
		URLs:      strings.Join(r.URLs, "&"),
	}
}

// addVerbs adds new verbs into a Rule.
// The duplicates in `r.Verbs` will be removed, and then `r.Verbs` will be sorted.
func (r *Rule) addVerbs(verbs []string) {
	r.Verbs = removeDupAndSort(append(r.Verbs, verbs...))
}

// normalize removes duplicates from each field of a Rule, and sorts each field.
func (r *Rule) normalize() {
	r.Groups = removeDupAndSort(r.Groups)
	r.Resources = removeDupAndSort(r.Resources)
	r.Verbs = removeDupAndSort(r.Verbs)
	r.URLs = removeDupAndSort(r.URLs)
}

// removeDupAndSort removes duplicates in strs, sorts the items, and returns a
// new slice of strings.
func removeDupAndSort(strs []string) []string {
	set := make(map[string]bool)
	for _, str := range strs {
		if _, ok := set[str]; !ok {
			set[str] = true
		}
	}

	var result []string
	for str := range set {
		result = append(result, str)
	}
	sort.Strings(result)
	return result
}

// ToRule converts this rule to its Kubernetes API form.
func (r *Rule) ToRule() rbacv1.PolicyRule {
	// fix the group names first, since letting people type "core" is nice
	for i, group := range r.Groups {
		if group == "core" {
			r.Groups[i] = ""
		}
	}
	return rbacv1.PolicyRule{
		APIGroups:       r.Groups,
		Verbs:           r.Verbs,
		Resources:       r.Resources,
		NonResourceURLs: r.URLs,
	}
}

// +controllertools:marker:generateHelp

// Generator generates ClusterRole objects.
type Generator struct {
	// RoleName sets the name of the generated ClusterRole.
	RoleName string
}

func (Generator) RegisterMarkers(into *markers.Registry) error {
	if err := into.Register(RuleDefinition); err != nil {
		return err
	}
	into.AddHelp(RuleDefinition, Rule{}.Help())
	return nil
}

// GenerateClusterRole generates a rbacv1.ClusterRole object
func GenerateClusterRole(ctx *genall.GenerationContext, roleName string) (*rbacv1.ClusterRole, error) {
	rules := make(map[ruleKey]*Rule)
	for _, root := range ctx.Roots {
		markerSet, err := markers.PackageMarkers(ctx.Collector, root)
		if err != nil {
			root.AddError(err)
		}

		// all the Rules having the same ruleKey will be merged into the first Rule
		for _, markerValue := range markerSet[RuleDefinition.Name] {
			rule := markerValue.(Rule)
			key := rule.key()
			if _, ok := rules[key]; !ok {
				rules[key] = &rule
				continue
			}
			rules[key].addVerbs(rule.Verbs)
		}
	}

	if len(rules) == 0 {
		return nil, nil
	}

	// sort the Rules in rules according to their ruleKeys
	keys := make([]ruleKey, 0)
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Sort(ruleKeys(keys))

	var policyRules []rbacv1.PolicyRule
	for _, key := range keys {
		policyRules = append(policyRules, rules[key].ToRule())

	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		Rules: policyRules,
	}, nil
}

func (g Generator) Generate(ctx *genall.GenerationContext) error {
	clusterRole, err := GenerateClusterRole(ctx, g.RoleName)
	if err != nil {
		return err
	}

	if clusterRole == nil {
		return nil
	}

	if err := ctx.WriteYAML("role.yaml", *clusterRole); err != nil {
		return err
	}

	return nil
}
