package main

import (
	"log"

	"github.com/simonswine/kube-lego/acme"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/util/intstr"
)

var AppName = "kube-lego"
var AppVersion = "unknown"
var AppGitCommit = ""
var AppGitState = ""

type KubeLego struct {
	LegoClient      *acme.Client
	LegoURL         string
	LegoEmail       string
	LegoSecretName  string
	LegoServiceName string
	LegoIngressName string
	LegoHTTPPort    intstr.IntOrString
	legoUser        *LegoUser
	KubeClient      *client.Client
}

func NewKubeLego() *KubeLego {
	return &KubeLego{}
}

func Version() string {
	version := AppVersion
	if len(AppGitCommit) > 0 {
		version += "-"
		version += AppGitCommit[0:8]
	}
	if len(AppGitState) > 0 && AppGitState != "clean" {
		version += "-"
		version += AppGitState
	}
	return version
}

func main() {
	log.Printf("%s %s starting", AppName, Version())

	kl := NewKubeLego()

	err := kl.InitKube()
	if err != nil {
		log.Fatal(err)
	}

	err = kl.InitLego()
	if err != nil {
		log.Fatal(err)
	}

	kl.WatchConfig()
}
