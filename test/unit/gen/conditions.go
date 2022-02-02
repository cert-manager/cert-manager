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

package gen

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type IssuerConditionModifier func(*v1.IssuerCondition)

func IssuerCondition(t v1.IssuerConditionType, mods ...IssuerConditionModifier) *v1.IssuerCondition {
	c := &v1.IssuerCondition{
		Type: t,
	}
	for _, m := range mods {
		m(c)
	}
	return c
}

func IssuerConditionFrom(c *v1.IssuerCondition, mods ...IssuerConditionModifier) *v1.IssuerCondition {
	c = c.DeepCopy()
	for _, m := range mods {
		m(c)
	}
	return c
}

func SetIssuerConditionStatus(s cmmeta.ConditionStatus) IssuerConditionModifier {
	return func(c *v1.IssuerCondition) {
		c.Status = s
	}
}

func SetIssuerConditionLastTransitionTime(t *metav1.Time) IssuerConditionModifier {
	return func(c *v1.IssuerCondition) {
		c.LastTransitionTime = t
	}
}

func SetIssuerConditionReason(s string) IssuerConditionModifier {
	return func(c *v1.IssuerCondition) {
		c.Reason = s
	}
}

func SetIssuerConditionMessage(s string) IssuerConditionModifier {
	return func(c *v1.IssuerCondition) {
		c.Message = s
	}
}
