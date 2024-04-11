package v1alpha1

import (
	"encoding/json"
	"github.com/cert-manager/cert-manager/pkg/apis/config/cainjector/v1alpha1"
	"os"
	"reflect"
	"testing"
)

const TestFileLocation = "testdata/defaults.json"

func TestCAInjectorConfigurationDefaults(t *testing.T) {
	if os.Getenv("UPDATE_DEFAULTS") == "true" {
		config := &v1alpha1.CAInjectorConfiguration{}
		SetObjectDefaults_CAInjectorConfiguration(config)
		defaultData, err := json.Marshal(config)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(TestFileLocation, defaultData, 0644); err != nil {
			t.Fatal(err)
		}
		t.Log("cainjector api defaults updated")
	}
	tests := []struct {
		name   string
		config *v1alpha1.CAInjectorConfiguration
	}{
		{
			"cainjection",
			&v1alpha1.CAInjectorConfiguration{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetObjectDefaults_CAInjectorConfiguration(tt.config)

			var expected *v1alpha1.CAInjectorConfiguration
			expectedData, err := os.ReadFile(TestFileLocation)
			err = json.Unmarshal(expectedData, &expected)

			if err != nil {
				t.Fatal("testfile not found")
			}

			if !reflect.DeepEqual(tt.config, expected) {
				prettyExpected, _ := json.MarshalIndent(expected, "", "\t")
				prettyGot, _ := json.MarshalIndent(tt.config, "", "\t")
				t.Errorf("expected defaults\n %v \n but got \n %v", string(prettyExpected), string(prettyGot))
			}
		})
	}
}
