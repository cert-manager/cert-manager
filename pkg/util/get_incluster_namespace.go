package util

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

var ErrNotInCluster = errors.New("not running in a cluster")

// GetInClusterNamespace returns the Kubernetes namespace of the Pod in which
// this process is running in a Kubernetes cluster.
// It checks for a well known namespace file path which is mounted into all
// Kubernetes Pods.
// Copied from controller-runtime
// https://github.com/kubernetes-sigs/controller-runtime/blob/1e4d87c9f9e15e4a58bb81909dd787f30ede7693/pkg/leaderelection/leader_election.go#L104-L119
func GetInClusterNamespace() (string, error) {
	// Check whether the namespace file exists.
	// If not, we are not running in cluster so can't guess the namespace.
	_, err := os.Stat(inClusterNamespacePath)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("%w: %v", ErrNotInCluster, err)
	} else if err != nil {
		return "", fmt.Errorf("error checking namespace file: %v", err)
	}

	// Load the namespace file and return its content
	namespace, err := ioutil.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "", fmt.Errorf("error reading namespace file: %v", err)
	}
	return string(namespace), nil
}
