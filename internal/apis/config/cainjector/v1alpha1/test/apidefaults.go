package main

import (
	"encoding/json"
	"fmt"
	v1alpha1_pkg "github.com/cert-manager/cert-manager/internal/apis/config/cainjector/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/apis/config/cainjector/v1alpha1"
	"os"
)

func main() {
	config := &v1alpha1.CAInjectorConfiguration{}
	v1alpha1_pkg.SetObjectDefaults_CAInjectorConfiguration(config)
	data, err := json.Marshal(config)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("./defaults.json", data, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("cainjector api defaults updated")
}
