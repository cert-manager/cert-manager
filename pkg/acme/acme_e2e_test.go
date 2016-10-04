package acme

import (
	"errors"
	"io/ioutil"
	"net/http"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/golang/mock/gomock"
	"github.com/jetstack/kube-lego/pkg/mocks"
	"k8s.io/kubernetes/pkg/util/intstr"
)

func TestAcme_E2E(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	log := logrus.WithField("context", "test-mock")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	// mock kube lego
	mockKL := mocks.NewMockKubeLego(ctrl)
	mockKL.EXPECT().Log().AnyTimes().Return(log)
	mockKL.EXPECT().Version().AnyTimes().Return("mocked-version")
	mockKL.EXPECT().LegoHTTPPort().AnyTimes().Return(intstr.FromInt(8181))
	mockKL.EXPECT().AcmeUser().MinTimes(1).Return(nil, errors.New("I am only mocked"))
	mockKL.EXPECT().LegoURL().MinTimes(1).Return("https://acme-staging.api.letsencrypt.org/directory")
	mockKL.EXPECT().LegoEmail().MinTimes(1).Return("kube-lego-e2e@example.com")
	mockKL.EXPECT().SaveAcmeUser(gomock.Any()).MinTimes(1).Return(nil)

	// set up ngrok
	command := []string{"ngrok", "http", "--bind-tls", "false", "8181"}
	cmdNgrok := exec.Command(command[0], command[1:]...)
	err := cmdNgrok.Start()
	if err != nil {
		t.Skip("Skipping e2e test as ngrok executable is not available: ", err)
	}
	defer cmdNgrok.Process.Kill()

	// get domain main for forwarding the acme validation
	regexDomain := regexp.MustCompile("http://([a-z0-9]+.\\.ngrok\\.io)")
	var domain string
	for {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get("http://localhost:4040/status")
		if err != nil {
			log.Warn(err)
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Warn(err)
			continue
		}

		matched := regexDomain.FindStringSubmatch(string(body))
		if matched == nil {
			continue
		}

		domain = matched[1]
		log.Infof("kube-lego domain is %s", domain)

		break
	}

	stopCh := make(chan struct{})
	a := New(mockKL)
	go a.RunServer(stopCh)

	log.Infof("trying to obtain a certificate for the domain")
	a.ObtainCertificate([]string{domain})

}
