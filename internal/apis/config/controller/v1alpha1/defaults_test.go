package v1alpha1

import (
	"encoding/json"
	"github.com/cert-manager/cert-manager/pkg/apis/config/controller/v1alpha1"
	"os"
	"reflect"
	"testing"
)

const TestFileLocation = "testdata/defaults.json"

func TestControllerConfigurationDefaults(t *testing.T) {
	if os.Getenv("UPDATE_DEFAULTS") == "true" {
		config := &v1alpha1.ControllerConfiguration{}
		SetObjectDefaults_ControllerConfiguration(config)
		defaultData, err := json.Marshal(config)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(TestFileLocation, defaultData, 0644); err != nil {
			t.Fatal(err)
		}
		t.Log("controller api defaults updated")
	}
	tests := []struct {
		name   string
		config *v1alpha1.ControllerConfiguration
	}{
		{
			"v1alpha1",
			&v1alpha1.ControllerConfiguration{},
		},
	}
	for _, tt := range tests {
		SetObjectDefaults_ControllerConfiguration(tt.config)

		var expected *v1alpha1.ControllerConfiguration
		expectedData, err := os.ReadFile(TestFileLocation)
		err = json.Unmarshal(expectedData, &expected)

		// need re-initialised post-unmarshal to avoid nil slice
		SetDefaults_ACMEHTTP01Config(&expected.ACMEHTTP01Config)
		SetDefaults_ACMEDNS01Config(&expected.ACMEDNS01Config)

		if err != nil {
			t.Fatal("testfile not found")
		}

		if !reflect.DeepEqual(tt.config, expected) {
			prettyExpected, _ := json.MarshalIndent(expected, "", "\t")
			prettyGot, _ := json.MarshalIndent(tt.config, "", "\t")
			t.Errorf("expected defaults\n %v \n but got \n %v", string(prettyExpected), string(prettyGot))
		}
	}
}
