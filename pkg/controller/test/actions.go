package test

import (
	"encoding/json"
	"log"
	"reflect"

	"github.com/kr/pretty"
	coretesting "k8s.io/client-go/testing"
)

type ActionMatchFn func(coretesting.Action, coretesting.Action) bool

type Action interface {
	Action() coretesting.Action
	Matches(coretesting.Action) bool
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

func (a *customMatchAction) Matches(act coretesting.Action) bool {
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

func (a *action) Matches(act coretesting.Action) bool {
	matches := reflect.DeepEqual(a.action, act)
	if matches == true {
		return true
	}

	objAct, ok := act.(coretesting.CreateAction)
	if !ok {
		return false
	}
	objExp, ok := a.action.(coretesting.CreateAction)
	if !ok {
		return false
	}

	bExp, _ := json.MarshalIndent(objExp, "", "\t")
	bAct, _ := json.MarshalIndent(objAct, "", "\t")
	log.Printf("Expected: %s", string(bExp))
	log.Printf("Actual: %s", string(bAct))
	log.Printf("Unexpected difference between actions: %s", pretty.Diff(objExp.GetObject(), objAct.GetObject()))

	return false
}
