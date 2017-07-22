package simple

import "fmt"

// CA is a simple CA implementation backed by the Kubernetes API server.
// A secret resource is used to store a CA public and private key that is then
// used to sign certificates.
type CA struct {
}

func (c *CA) Setup() error {
	return fmt.Errorf("not implemented")
}
