package dyndns

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"

	"github.com/stretchr/testify/assert"
	"k8s.io/klog"
)

var (
	dynCustomerName string
	dynUsername     string
	dynPassword     string
	dynZoneName     string
	dynLiveTest     bool
)

func init() {
	klog.Info("Starting DynDNS test")
	dynCustomerName = os.Getenv("DYN_CUSTOMER_NAME")
	dynUsername = os.Getenv("DYN_USERNAME")
	dynPassword = os.Getenv("DYN_PASSWORD")
	dynZoneName = os.Getenv("DYN_ZONE_NAME")
	if len(dynCustomerName) > 0 && len(dynUsername) > 0 && len(dynPassword) > 0 && len(dynZoneName) > 0 {
		dynLiveTest = true
	}
}

func TestLiveDynDnsPresent(t *testing.T) {
	if !dynLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProvider(dynCustomerName, dynUsername, dynPassword, dynZoneName, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(dynZoneName, "testing123123", "123d==")
	assert.NoError(t, err)
}

func TestLiveDynDnsCleanUp(t *testing.T) {
	if !dynLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 5)

	provider, err := NewDNSProvider(dynCustomerName, dynUsername, dynPassword, dynZoneName, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(dynZoneName, "", "123d==")
	assert.NoError(t, err)
}
