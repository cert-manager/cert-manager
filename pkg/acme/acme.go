package acme

import (
	"fmt"
	"net/http"
	"net"

	"github.com/simonswine/kube-lego/pkg/kubelego_const"

	"github.com/Sirupsen/logrus"
	"github.com/etix/stoppableListener"
)

func New(kubeleg kubelego.KubeLego) *Acme {
	a := &Acme{
		kubelego: kubeleg,
	}
	return a
}

func (a *Acme) Log() *logrus.Entry {
	return a.kubelego.Log().WithField("context", "acme")
}

func (a *Acme) handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, "unimplemented - 500")
}

func (a *Acme) RunServer(stopCh <-chan struct{}) {
	port := a.kubelego.LegoHTTPPort()
	version := a.kubelego.Version()

	// listen on port
	listener, err := net.Listen("tcp", port)
	if err != nil {
		a.Log().Fatalf("error starting http server on %s: %s", port, err)
	}

	a.Log().Infof("server listening on http://%s/", port)

	stoppable := stoppableListener.Handle(listener)

	// handle stop signal
	go func() {
		<-stopCh
		a.Log().Infof("stopping server listening on http://%s/", port)
		stoppable.Stop <- true
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "kube-lego %s backend - 404", version)
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	http.HandleFunc(kubelego.AcmeHttpChallengePath, a.handleChallenge)

	http.Serve(stoppable, nil)
}

