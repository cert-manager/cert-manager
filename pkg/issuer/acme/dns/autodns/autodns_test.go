/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package autodns

import (
	"github.com/actano/autodns-api-go/pkg/zone"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var (
	autoDnsLiveTest bool
	autoDnsUsername string
	autoDnsPassword string
	autoDnsContext  string
	autoDnsDomain   string
)

func init() {
	autoDnsUsername = os.Getenv("AUTODNS_USERNAME")
	autoDnsPassword = os.Getenv("AUTODNS_PASSWORD")
	autoDnsContext = os.Getenv("AUTODNS_CONTEXT")
	autoDnsDomain = os.Getenv("AUTODNS_DOMAIN")

	if len(autoDnsUsername) > 0 && len(autoDnsPassword) > 0 && len(autoDnsContext) > 0 {
		autoDnsLiveTest = true
	}
}

func TestAutoDnsPresent(t *testing.T) {
	autodns := NewDNSProvider("username", "password", "context", util.RecursiveNameservers)

	zoneApiMock := mockZoneApi()
	autodns.client.Zone = zoneApiMock

	expectedArgs := updateBulkArgs{
		ZoneName: "example.com",
		Adds: []zone.ResourceRecord{
			{
				Name:  "_acme-challenge.test.example.com.",
				Type:  "TXT",
				TTL:   300,
				Value: "dns01-key",
			},
		},
		Removes: nil,
	}

	err := autodns.Present("test.example.com", "_acme-challenge.test.example.com.", "dns01-key")
	assert.NoError(t, err)
	assert.Equal(t, expectedArgs, zoneApiMock.UpdateBulkArgs)
}

func TestAutoDnsCleanUp(t *testing.T) {
	autodns := NewDNSProvider("username", "password", "context", util.RecursiveNameservers)

	zoneApiMock := mockZoneApi()
	autodns.client.Zone = zoneApiMock

	expectedArgs := updateBulkArgs{
		ZoneName: "example.com",
		Adds:     nil,
		Removes: []zone.ResourceRecord{
			{
				Name:  "_acme-challenge.test.example.com.",
				Type:  "TXT",
				TTL:   300,
				Value: "dns01-key",
			},
		},
	}

	err := autodns.CleanUp("test.example.com", "_acme-challenge.test.example.com.", "dns01-key")
	assert.NoError(t, err)
	assert.Equal(t, expectedArgs, zoneApiMock.UpdateBulkArgs)
}

func TestLiveAutoDnsPresent(t *testing.T) {
	if !autoDnsLiveTest {
		t.Skip("skipping live test")
	}

	expectedRecord := zone.ResourceRecord{
		Name:  "_acme-challenge",
		Type:  "TXT",
		TTL:   300,
		Value: "autoDnsLiveTest",
	}

	autodns := NewDNSProvider(autoDnsUsername, autoDnsPassword, autoDnsContext, util.RecursiveNameservers)

	err := autodns.Present(autoDnsDomain, "_acme-challenge."+autoDnsDomain+".", "autoDnsLiveTest")
	assert.NoError(t, err)

	zones, err := autodns.client.Zone.GetZoneInfo(autoDnsDomain)
	assert.NoError(t, err)
	assert.True(t, hasRecord(zones, expectedRecord))
}

func TestLiveAutoDnsCleanUp(t *testing.T) {
	if !autoDnsLiveTest {
		t.Skip("skipping live test")
	}

	expectedRecord := zone.ResourceRecord{
		Name:  "_acme-challenge",
		Type:  "TXT",
		TTL:   300,
		Value: "autoDnsLiveTest",
	}

	autodns := NewDNSProvider(autoDnsUsername, autoDnsPassword, autoDnsContext, util.RecursiveNameservers)

	err := autodns.CleanUp(autoDnsDomain, "_acme-challenge."+autoDnsDomain+".", "autoDnsLiveTest")
	assert.NoError(t, err)

	zones, err := autodns.client.Zone.GetZoneInfo(autoDnsDomain)
	assert.NoError(t, err)
	assert.False(t, hasRecord(zones, expectedRecord))
}

type updateBulkArgs struct {
	ZoneName string
	Adds     []zone.ResourceRecord
	Removes  []zone.ResourceRecord
}

type zoneServiceMock struct {
	UpdateBulkResult error
	UpdateBulkArgs   updateBulkArgs
}

func (z *zoneServiceMock) UpdateBulk(zoneName string, adds, removes []zone.ResourceRecord) error {
	z.UpdateBulkArgs = updateBulkArgs{
		ZoneName: zoneName,
		Adds:     adds,
		Removes:  removes,
	}
	return z.UpdateBulkResult
}

func (z *zoneServiceMock) GetZoneInfo(zoneName string) (*zone.ZoneInfo, error) {
	return nil, nil
}

func mockZoneApi() *zoneServiceMock {
	return &zoneServiceMock{}
}

func hasRecord(zoneInfo *zone.ZoneInfo, record zone.ResourceRecord) bool {
	found := false

	for _, v := range zoneInfo.Records {
		if record.Name == v.Name && record.Type == v.Type && record.Value == v.Value && record.TTL == v.TTL {
			found = true
		}
	}

	return found
}
