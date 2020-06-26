package ocidns

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"

	"io/ioutil"

	"github.com/stretchr/testify/assert"

	//  "fmt"
	yaml "gopkg.in/yaml.v2"
)

var (
	ociDnsZone         string
	ociCompartmentId   string
	ociRegion          string
	ociTenancyId       string
	ociUserId          string
	ociUserFingerprint string
	ociKeyPath         string
	ociLiveTest        bool
)

var ociConfigBytes []byte
var fqdn string

func init() {

	ociDnsZone = os.Getenv("OCI_ZONE_NAME")
	ociRegion = os.Getenv("OCI_REGION")
	ociTenancyId = os.Getenv("OCI_TENANCY_ID")
	ociUserId = os.Getenv("OCI_USER_ID")
	ociUserFingerprint = os.Getenv("OCI_FINGERPRINT")
	ociKeyPath = os.Getenv(("OCI_KEYPATH"))
	ociCompartmentId = os.Getenv("OCI_COMPARTMENT_ID")

	if len(ociDnsZone) > 0 &&
		len(ociRegion) > 0 &&
		len(ociTenancyId) > 0 &&
		len(ociUserId) > 0 &&
		len(ociUserFingerprint) > 0 &&
		len(ociKeyPath) > 0 {
		ociLiveTest = true
		loadConfig()
	}
}

func loadConfig() {

	ociKeyData, err := ioutil.ReadFile(ociKeyPath)
	if err != nil {

	}

	ociAuthConfig := OCIAuthConfig{
		Region:      ociRegion,
		TenancyID:   ociTenancyId,
		UserID:      ociUserId,
		PrivateKey:  string(ociKeyData),
		Fingerprint: ociUserFingerprint,
		Passphrase:  "",
	}

	ociConfig := OCIConfig{
		Auth:          ociAuthConfig,
		CompartmentID: ociCompartmentId,
	}

	ociConfigBytes, err = yaml.Marshal(ociConfig)
	fqdn = "_acme-challenge." + ociDnsZone + "."
	// debug your Config if Needed, uncomment
	//	fmt.Println(string(ociConfigBytes))

}

//func NewDNSProvider(
//	useInstancePrincipals bool,
//	zoneName string,
//	compartmentId string,
//	keyData []byte,
//	dns01Nameservers []string) (*DNSProvider, error) {
func TestLiveOciDnsPresent(t *testing.T) {
	if !ociLiveTest {
		t.Skip("skipping live test")
	}
	provider, err := NewDNSProvider(
		false,
		ociDnsZone,
		"",
		ociConfigBytes,
		util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(ociDnsZone, fqdn, "12345==")
	assert.NoError(t, err)
}

func TestLiveOciDnsCleanUp(t *testing.T) {
	if !ociLiveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 10)

	provider, err := NewDNSProvider(
		false,
		ociDnsZone,
		"",
		ociConfigBytes,
		util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(ociDnsZone, fqdn, "12345==")
	assert.NoError(t, err)
}
