/*
Copyright 2019 The Jetstack cert-manager contributors.

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

type ActionMatchFn func(coretesting.Action, coretesting.Action) error

type Action interface {
	Action() coretesting.Action
	Matches(coretesting.Action) error
}

type customMatchAction struct {
	action  coretesting.Action
	matchFn ActionMatchFn
}

var _ Action = &customMatchAction{}

func NewCustomMatch(a coretesting.Action, matchFn ActionMatchFn) Action {
	return &customMatchAction{
		action:  a,
		matchFn: matchFn,
	}
}

func (a *customMatchAction) Action() coretesting.Action {
	return a.action
}

func (a *customMatchAction) Matches(act coretesting.Action) error {
	return a.matchFn(a.action, act)
}

type action struct {
	action coretesting.Action
}

var _ Action = &action{}

func NewAction(a coretesting.Action) Action {
	return &action{
		action: a,
	}
}

func (a *action) Action() coretesting.Action {
	return a.action
}

func (a *action) Matches(act coretesting.Action) error {
	matches := reflect.DeepEqual(a.action, act)
	if matches == true {
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
