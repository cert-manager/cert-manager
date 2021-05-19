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

package test

import (
	"fmt"
	"reflect"

	"github.com/kr/pretty"
	coretesting "k8s.io/client-go/testing"
)

// ActionMatchFn is a type of custom matcher for two Actions.
type ActionMatchFn func(coretesting.Action, coretesting.Action) error

// Action implements a getter and a matcher for coretesting.Action type.
type Action interface {
	Action() coretesting.Action
	Matches(coretesting.Action) error
}

type customMatchAction struct {
	action  coretesting.Action
	matchFn ActionMatchFn
}

var _ Action = &customMatchAction{}

// NewCustomMatch takes an Action and a matcher function and returns a wrapper
// that can be used to compare this Action with another one.
func NewCustomMatch(a coretesting.Action, matchFn ActionMatchFn) Action {
	return &customMatchAction{
		action:  a,
		matchFn: matchFn,
	}
}

// Action is a getter for customMatchAction.action.
func (a *customMatchAction) Action() coretesting.Action {
	return a.action
}

// Matches compares the action of customMatchAction with another Action.
func (a *customMatchAction) Matches(act coretesting.Action) error {
	return a.matchFn(a.action, act)
}

type action struct {
	action coretesting.Action
}

var _ Action = &action{}

// NewAction takes coretesting.Action and wraps it with action.
func NewAction(a coretesting.Action) Action {
	return &action{
		action: a,
	}
}

// Action is a getter for action.action.
func (a *action) Action() coretesting.Action {
	return a.action
}

// Matches compares action.action with another Action.
func (a *action) Matches(act coretesting.Action) error {
	matches := reflect.DeepEqual(a.action, act)
	if matches {
		return nil
	}

	objAct, ok := act.(coretesting.CreateAction)
	if !ok {
		return nil
	}
	objExp, ok := a.action.(coretesting.CreateAction)
	if !ok {
		return nil
	}

	return fmt.Errorf("unexpected difference between actions: %s", pretty.Diff(objExp.GetObject(), objAct.GetObject()))
}
