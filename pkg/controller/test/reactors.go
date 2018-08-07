package test

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"
)

func NTimesReactor(f coretesting.ReactionFunc, numberCalls int) coretesting.ReactionFunc {
	calls := 0
	return func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		if numberCalls == calls {
			return false, nil, nil
		}
		handled, ret, err = f(action)
		if handled {
			calls++
		}
		return handled, ret, err
	}
}

func ObjectCreatedReactor(t *testing.T, b *Builder, expectedObj runtime.Object) coretesting.ReactionFunc {
	return func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		createAction, ok := action.(coretesting.CreateAction)
		if !ok {
			return
		}
		obj, ok := createAction.GetObject().(runtime.Object)
		if !ok {
			t.Errorf("object passed to Create does not implement runtime.Object")
		}

		if !reflect.DeepEqual(obj, expectedObj) {
			t.Errorf("expected %+v to equal %+v", obj, expectedObj)
		}

		return true, obj, nil
	}
}

func ObjectDeletedReactor(t *testing.T, b *Builder, obj runtime.Object) coretesting.ReactionFunc {
	metaExpObj := obj.(metav1.Object)
	return func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		delAction, ok := action.(coretesting.DeleteAction)
		if !ok {
			return
		}

		namespace, name := delAction.GetNamespace(), delAction.GetName()
		if namespace != metaExpObj.GetNamespace() || name != metaExpObj.GetName() {
			t.Errorf("expected %s/%s to equal %s/%s", namespace, name, metaExpObj.GetNamespace(), metaExpObj.GetName())
		}

		return true, obj, nil
	}
}
