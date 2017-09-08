package util

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	clientset "github.com/jetstack-experimental/cert-manager/pkg/client/typed/certmanager/v1alpha1"
)

func WaitForIssuerReady(cl clientset.IssuerInterface, name string) error {
	return wait.PollImmediate(500*time.Millisecond, wait.ForeverTestTimeout,
		func() (bool, error) {
			issuer, err := cl.Get(name, metav1.GetOptions{})
			if nil != err {
				return false, fmt.Errorf("error getting Broker %v: %v", name, err)
			}

			if issuer.Status.Ready {
				return true, nil
			}

			return false, nil
		},
	)
}
