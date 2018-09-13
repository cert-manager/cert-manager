package clusterissuers

import (
	"reflect"
	"runtime/debug"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgotesting "k8s.io/client-go/testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func newFakeIssuerWithStatus(name string, status v1alpha1.IssuerStatus) *v1alpha1.ClusterIssuer {
	return &v1alpha1.ClusterIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Status: status,
	}
}

func TestSync(t *testing.T) {

}

func TestUpdateIssuerStatus(t *testing.T) {
	f := &controllerFixture{}
	f.Setup(t)
	defer f.Finish(t)

	c := f.Controller
	fakeClient := f.Builder.FakeCMClient()
	assertNumberOfActions(t, fatalf, filter(fakeClient.Actions()), 0)

	originalIssuer := newFakeIssuerWithStatus("test", v1alpha1.IssuerStatus{})

	issuer, err := fakeClient.CertmanagerV1alpha1().ClusterIssuers().Create(originalIssuer)
	assertErrIsNil(t, fatalf, err)

	assertNumberOfActions(t, fatalf, filter(fakeClient.Actions()), 1)

	newStatus := v1alpha1.IssuerStatus{
		Conditions: []v1alpha1.IssuerCondition{
			{
				Type:   v1alpha1.IssuerConditionReady,
				Status: v1alpha1.ConditionTrue,
			},
		},
	}

	issuerCopy := issuer.DeepCopy()
	issuerCopy.Status = newStatus
	_, err = c.updateIssuerStatus(issuer, issuerCopy)
	assertErrIsNil(t, fatalf, err)

	actions := filter(fakeClient.Actions())
	assertNumberOfActions(t, fatalf, actions, 2)

	action := actions[1]
	updateAction := assertIsUpdateAction(t, errorf, action)

	obj := updateAction.GetObject()
	issuer = assertIsClusterIssuer(t, errorf, obj)

	assertDeepEqual(t, errorf, newStatus, issuer.Status)
}

func assertIsUpdateAction(t *testing.T, f failfFunc, action clientgotesting.Action) clientgotesting.UpdateAction {
	updateAction, ok := action.(clientgotesting.UpdateAction)
	if !ok {
		f(t, "action %#v does not implement interface UpdateAction")
	}
	return updateAction
}

func assertNumberOfActions(t *testing.T, f failfFunc, actions []clientgotesting.Action, number int) {
	if len(actions) != number {
		f(t, "expected %d actions, but got %d", number, len(actions))
	}
}

func assertErrIsNil(t *testing.T, f failfFunc, err error) {
	if err != nil {
		f(t, err.Error())
	}
}

func assertIsClusterIssuer(t *testing.T, f failfFunc, obj runtime.Object) *v1alpha1.ClusterIssuer {
	issuer, ok := obj.(*v1alpha1.ClusterIssuer)
	if !ok {
		f(t, "expected runtime.Object to be of type *v1alpha1.Issuer, but it was %#v", obj)
	}
	return issuer
}

func assertDeepEqual(t *testing.T, f failfFunc, left, right interface{}) {
	if !reflect.DeepEqual(left, right) {
		f(t, "object '%#v' does not equal '%#v'", left, right)
	}
}

func filter(in []clientgotesting.Action) []clientgotesting.Action {
	var out []clientgotesting.Action
	for _, i := range in {
		if i.GetVerb() != "list" && i.GetVerb() != "watch" {
			out = append(out, i)
		}
	}
	return out
}

// failfFunc is a type that defines the common signatures of T.Fatalf and
// T.Errorf.
type failfFunc func(t *testing.T, msg string, args ...interface{})

func fatalf(t *testing.T, msg string, args ...interface{}) {
	t.Log(string(debug.Stack()))
	t.Fatalf(msg, args...)
}

func errorf(t *testing.T, msg string, args ...interface{}) {
	t.Log(string(debug.Stack()))
	t.Errorf(msg, args...)
}
