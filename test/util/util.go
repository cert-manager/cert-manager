package util

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/golang/glog"
	"github.com/jetstack-experimental/cert-manager/pkg/apis/certmanager/v1alpha1"
	clientset "github.com/jetstack-experimental/cert-manager/pkg/client/typed/certmanager/v1alpha1"
)

// WaitForIssuerCondition waits for the status of the named issuer to contain
// a condition whose type and status matches the supplied one.
func WaitForIssuerCondition(client clientset.IssuerInterface, name string, condition v1alpha1.IssuerCondition) error {
	return wait.PollImmediate(500*time.Millisecond, wait.ForeverTestTimeout,
		func() (bool, error) {
			glog.V(5).Infof("Waiting for issuer %v condition %#v", name, condition)
			issuer, err := client.Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Issuer %v: %v", name, err)
			}

			return v1alpha1.IssuerHasCondition(issuer, condition), nil
		},
	)
}
