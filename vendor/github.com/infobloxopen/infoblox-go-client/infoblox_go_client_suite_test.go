package ibclient_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestInfobloxGoClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "InfobloxGoClient Suite")
}
