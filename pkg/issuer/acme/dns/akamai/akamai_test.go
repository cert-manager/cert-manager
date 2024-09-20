/*
Copyright 2020 The cert-manager Authors.

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

package akamai

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	dns "github.com/akamai/AkamaiOPEN-edgegrid-golang/configdns-v2"
	"github.com/stretchr/testify/assert"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

func testRecordBodyData() *dns.RecordBody {

	return &dns.RecordBody{
		Name:       "_acme-challenge.test.example.com",
		RecordType: "TXT",
		Target:     []string{`"` + "dns01-key" + `"`},
		TTL:        300,
	}
}

func testRecordBodyDataExist() *dns.RecordBody {

	return &dns.RecordBody{
		Name:       "_acme-challenge.test.example.com",
		RecordType: "TXT",
		Target:     []string{`"` + "dns01-key" + `"`, `"` + "dns01-key-stub" + `"`},
		TTL:        300,
	}
}

// OpenEdgegrid DNS Stub
type StubOpenDNSConfig struct {
	FuncOutput map[string]interface{}
	FuncErrors map[string]error
}

func findStubHostedDomainByFqdn(_ context.Context, fqdn string, ns []string) (string, error) {
	return "test.example.com", nil

}

func stubIsNotFoundTrue(err error) bool {

	return true
}

func stubIsNotFoundFalse(err error) bool {

	return false
}

// TestNewDNSProvider performs sanity check on provider init
func TestNewDNSProvider(t *testing.T) {

	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)
	// sample couple important fields
	assert.Equal(t, akamai.serviceConsumerDomain, "akamai.example.com")
	assert.Equal(t, fmt.Sprintf("%T", akamai.dnsclient), "*akamai.OpenDNSConfig")

}

// TestPresentBasicFlow tests basic flow, e.g. no record exists.
func TestPresentBasicFlow(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundTrue
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = nil
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["RecordSave"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.NoError(t, akamai.Present(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key"))

}

// TestPresentExists tests flow with existing record.
func TestPresentExists(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["RecordUpdate"] = testRecordBodyDataExist()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.NoError(t, akamai.Present(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key-stub"))

}

// TestPresentValueExists tests flow with existing record.
func TestPresentValueExists(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.NoError(t, akamai.Present(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key"))

}

func TestPresentFailGetRecord(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = nil
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["GetRecord"] = fmt.Errorf("Failed Get Test")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.Error(t, akamai.Present(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key"))

}

func TestPresentFailSaveRecord(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundTrue
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = nil
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save fail")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.Error(t, akamai.Present(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key"))

}

func TestPresentFailUpdateRecord(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["RecordUpdate"] = testRecordBodyDataExist()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update failed")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.Error(t, akamai.Present(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key-stub"))

}

// TestCleanUpBasicFlow tests flow with existing record.
func TestCleanUpBasicFlow(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["RecordDelete"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")

	assert.NoError(t, akamai.CleanUp(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key"))

}

// TestPresentExists tests flow with existing record.
func TestCleanUpExists(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["RecordUpdate"] = testRecordBodyDataExist()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.NoError(t, akamai.CleanUp(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key-stub"))

}

// TestCleanUpExistsNoValue tests flow with existing record.
func TestCleanUpExistsNoValue(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.NoError(t, akamai.CleanUp(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key-stub"))

}

// TestCleanUpNoRecord tests flow with no existing record.
func TestCleanUpNoRecord(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundTrue // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = nil
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.NoError(t, akamai.CleanUp(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01"))

}

func TestCleanUpFailGetRecord(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = nil
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["GetRecord"] = fmt.Errorf("Failed Get Record")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.Error(t, akamai.CleanUp(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key"))

}

func TestCleanUpFailUpdateRecord(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = testRecordBodyDataExist()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["RecordUpdate"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update failed")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete not expected")

	assert.Error(t, akamai.CleanUp(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key-stub"))

}

func TestCleanUpFailDeleteRecord(t *testing.T) {
	akamai, err := NewDNSProvider("akamai.example.com", "token", "secret", "access-token", util.RecursiveNameservers)
	assert.NoError(t, err)

	akamai.findHostedDomainByFqdn = findStubHostedDomainByFqdn
	akamai.isNotFound = stubIsNotFoundFalse // ignored for this flow ...
	akamai.dnsclient = &StubOpenDNSConfig{FuncOutput: map[string]interface{}{}, FuncErrors: map[string]error{}}
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["GetRecord"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncOutput["RecordDelete"] = testRecordBodyData()
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordSave"] = fmt.Errorf("Save not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordUpdate"] = fmt.Errorf("Update not expected")
	akamai.dnsclient.(*StubOpenDNSConfig).FuncErrors["RecordDelete"] = fmt.Errorf("Delete failed")

	assert.Error(t, akamai.CleanUp(context.TODO(), "test.example.com", "_acme-challenge.test.example.com.", "dns01-key"))

}

// Stub Get Record
func (o StubOpenDNSConfig) GetRecord(zone string, name string, recordType string) (*dns.RecordBody, error) {

	var rec *dns.RecordBody

	err, ok := o.FuncErrors["GetRecord"]
	if ok {
		return nil, err
	}

	exp, ok := o.FuncOutput["GetRecord"]
	if ok {
		if exp == nil {
			return nil, fmt.Errorf("GetRecord: Unexpected nil")
		}
		rec = exp.(*dns.RecordBody)
		// compare passed with expected
		if name != rec.Name {
			return nil, fmt.Errorf("GetRecord: expected/actual Name don't match")
		}
		if recordType != rec.RecordType {
			return nil, fmt.Errorf("GetRecord: expected/actual Record Type don't match")
		}
	}

	return rec, nil

}

func (o StubOpenDNSConfig) RecordSave(rec *dns.RecordBody, zone string) error {

	exp, ok := o.FuncOutput["RecordSave"]
	if ok {
		// compare passed with expected
		if rec.Name != exp.(*dns.RecordBody).Name {
			return fmt.Errorf("RecordSave: expected/actual Name don't match")
		}
		if rec.RecordType != exp.(*dns.RecordBody).RecordType {
			return fmt.Errorf("RecordSave: expected/actual Record Type don't match")
		}
		if !reflect.DeepEqual(rec.Target, exp.(*dns.RecordBody).Target) {
			return fmt.Errorf("RecordSave: expected/actual Target don't match")
		}
		if rec.TTL != exp.(*dns.RecordBody).TTL {
			return fmt.Errorf("RecordSave: expected/actual TTL don't match")
		}
	}
	err, ok := o.FuncErrors["RecordSave"]
	if ok {
		return err
	}

	return nil

}

func (o StubOpenDNSConfig) RecordUpdate(rec *dns.RecordBody, zone string) error {

	exp, ok := o.FuncOutput["RecordUpdate"]
	if ok {
		// compare passed with expected
		if rec.Name != exp.(*dns.RecordBody).Name {
			return fmt.Errorf("RecordUpdate: expected/actual Name don't match")
		}
		if rec.RecordType != exp.(*dns.RecordBody).RecordType {
			return fmt.Errorf("RecordUpdate: expected/actual Record Type don't match")
		}
		if !reflect.DeepEqual(rec.Target, exp.(*dns.RecordBody).Target) {
			return fmt.Errorf("RecordUpdate: expected/actual Target don't match")
		}
		if rec.TTL != exp.(*dns.RecordBody).TTL {
			return fmt.Errorf("RecordUpdate: expected/actual TTL don't match")
		}
	}
	err, ok := o.FuncErrors["RecordUpdate"]
	if ok {
		return err
	}

	return nil
}

func (o StubOpenDNSConfig) RecordDelete(rec *dns.RecordBody, zone string) error {

	exp, ok := o.FuncOutput["RecordDelete"]
	if ok {
		// compare passed with expected
		if rec.Name != exp.(*dns.RecordBody).Name {
			return fmt.Errorf("RecordDelete: expected/actual Name don't match")
		}
		if rec.RecordType != exp.(*dns.RecordBody).RecordType {
			return fmt.Errorf("RecordDelete: expected/actual Record Type don't match")
		}
		if !reflect.DeepEqual(rec.Target, exp.(*dns.RecordBody).Target) {
			return fmt.Errorf("RecordDelete: expected/actual Target don't match")
		}
		if rec.TTL != exp.(*dns.RecordBody).TTL {
			return fmt.Errorf("RecordDelete: expected/actual TTL don't match")
		}
	}
	err, ok := o.FuncErrors["RecordDelete"]
	if ok {
		return err
	}

	return nil
}
