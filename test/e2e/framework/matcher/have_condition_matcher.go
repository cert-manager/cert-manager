/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package matcher

import (
	"fmt"
	"reflect"

	"github.com/onsi/gomega/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/test/e2e/framework"
)

// HaveCondition will wait for up to the
func HaveCondition(f *framework.Framework, condition interface{}) *conditionMatcher {
	return &conditionMatcher{
		f:         f,
		condition: condition,
	}
}

//// begin resource condition type mapping.
// modify this block of code to add support for new types

func toGenericCondition(c interface{}) (*genericCondition, error) {
	switch c := c.(type) {
	case cmapi.CertificateCondition:
		return buildGenericCondition(string(c.Type), string(c.Status), c.Reason), nil
	case cmapi.IssuerCondition:
		return buildGenericCondition(string(c.Type), string(c.Status), c.Reason), nil
	default:
		return nil, fmt.Errorf("unsupported condition type %T", c)
	}
}

func (c *conditionMatcher) getUpToDateResource(obj interface{}) (interface{}, error) {
	switch obj := obj.(type) {
	case *cmapi.Certificate:
		return c.f.CertManagerClientSet.CertmanagerV1alpha1().Certificates(obj.Namespace).Get(obj.Name, metav1.GetOptions{})
	case *cmapi.Issuer:
		return c.f.CertManagerClientSet.CertmanagerV1alpha1().Issuers(obj.Namespace).Get(obj.Name, metav1.GetOptions{})
	default:
		return nil, fmt.Errorf("unsupported resource type %T", c)
	}
}

func extractConditionSlice(obj interface{}) ([]interface{}, error) {
	var actualConditions []interface{}
	switch obj := obj.(type) {
	case *cmapi.Certificate:
		for _, c := range obj.Status.Conditions {
			actualConditions = append(actualConditions, c)
		}
	case *cmapi.Issuer:
		for _, c := range obj.Status.Conditions {
			actualConditions = append(actualConditions, c)
		}
	default:
		return nil, fmt.Errorf("unsupported resource type %T", obj)
	}
	return actualConditions, nil
}

//// end resource condition type mapping.

type conditionMatcher struct {
	f         *framework.Framework
	condition interface{}
}

type genericCondition struct {
	Type   *string
	Status *string
	Reason *string
}

func (g *genericCondition) String() string {
	t := "<nil>"
	s := "<nil>"
	r := "<nil>"
	if g.Type != nil {
		t = *g.Type
	}
	if g.Status != nil {
		s = *g.Status
	}
	if g.Reason != nil {
		r = *g.Reason
	}
	return fmt.Sprintf("Type: %q, Status: %q, Reason: %q", t, s, r)
}

var _ types.GomegaMatcher = &conditionMatcher{}

func (c *conditionMatcher) Match(actual interface{}) (bool, error) {
	expected, err := toGenericCondition(c.condition)
	if err != nil {
		return false, err
	}

	upToDateActual, err := c.getUpToDateResource(actual)
	if err != nil {
		return false, err
	}

	conditionsSlice, err := extractConditionSlice(upToDateActual)
	if err != nil {
		return false, err
	}

	for _, c := range conditionsSlice {
		g, err := toGenericCondition(c)
		if err != nil {
			return false, err
		}
		if matches(expected, g) {
			return true, nil
		}
	}

	return false, nil
}

func matches(expected, actual *genericCondition) bool {
	if expected.Type != nil {
		if !reflect.DeepEqual(expected.Type, actual.Type) {
			return false
		}
	}
	if expected.Status != nil {
		if !reflect.DeepEqual(expected.Status, actual.Status) {
			return false
		}
	}
	if expected.Reason != nil {
		if !reflect.DeepEqual(expected.Reason, actual.Reason) {
			return false
		}
	}
	return true
}

func buildGenericCondition(cType, status, reason string) *genericCondition {
	g := &genericCondition{}
	if cType != "" {
		g.Type = &cType
	}
	if status != "" {
		g.Status = &status
	}
	if reason != "" {
		g.Reason = &reason
	}
	return g
}

func (c *conditionMatcher) FailureMessage(actual interface{}) string {
	expected, err := toGenericCondition(c.condition)
	if err != nil {
		return "Did not have required condition"
	}

	upToDateActual, err := c.getUpToDateResource(actual)
	if err != nil {
		return "Did not have required condition"
	}

	conditionsSlice, err := extractConditionSlice(upToDateActual)
	if err != nil {
		return "Did not have required condition"
	}

	return fmt.Sprintf("Did not have expected condition (%s), had conditions: %v", expected.String(), conditionsSlice)
}

func (c *conditionMatcher) NegatedFailureMessage(actual interface{}) string {
	expected, err := toGenericCondition(c.condition)
	if err != nil {
		return "Condition found"
	}

	upToDateActual, err := c.getUpToDateResource(actual)
	if err != nil {
		return "Did not have required condition"
	}

	conditionsSlice, err := extractConditionSlice(upToDateActual)
	if err != nil {
		return "Did not have required condition"
	}

	return fmt.Sprintf("Found unexpected condition (%s), had conditions: %v", expected.String(), conditionsSlice)
}
