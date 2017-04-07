package acme

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"path"
	"strings"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"github.com/jetstack/kube-lego/pkg/utils"

	"github.com/Sirupsen/logrus"
)

func New(kubeLego kubelego.KubeLego) *Acme {
	a := &Acme{
		kubelego:              kubeLego,
		challengesHostToToken: map[string]string{},
		challengesTokenToKey:  map[string]string{},
		id:                    utils.RandomToken(16),
	}
	if kubeLego != nil {
		a.log = a.kubelego.Log().WithField("context", "acme")
		a.notFound = fmt.Sprintf("kube-lego (version %s) - 404 not found", kubeLego.Version())
	} else {
		a.log = logrus.WithField("context", "acme")
	}
	return a
}

func (a *Acme) Log() (log *logrus.Entry) {
	return a.log
}

func (a *Acme) Mux() *http.ServeMux {

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		} else {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, a.notFound)
		}
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	mux.HandleFunc(kubelego.AcmeHttpChallengePath+"/", a.handleChallenge)

	mux.HandleFunc(kubelego.AcmeHttpSelfTest, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, a.id)
	})

	// enable pprof in debug mode
	if logrus.GetLevel() == logrus.DebugLevel {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	return mux
}

func (a *Acme) handleChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	host := strings.Split(r.Host, ":")[0]
	basePath := path.Dir(r.URL.EscapedPath())
	token := path.Base(r.URL.EscapedPath())

	log := a.Log().WithFields(logrus.Fields{
		"host":     host,
		"basePath": basePath,
		"token":    token,
	})

	// wrong base path
	if basePath != path.Clean(kubelego.AcmeHttpChallengePath) {
		log.Debugf("base path not matching '%s'", kubelego.AcmeHttpChallengePath)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, a.notFound)
		return
	}

	// read shared storage
	a.challengesMutex.RLock()
	tokenExpected, okHost := a.challengesHostToToken[host]
	key, okToken := a.challengesTokenToKey[token]
	a.challengesMutex.RUnlock()

	if !okHost {
		log.Debugf("host not found")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, a.notFound)
		return
	}

	if !okToken {
		log.Debugf("token not found")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, a.notFound)
		return
	}

	if tokenExpected != token {
		log.Debugf("token not matching expected token")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, a.notFound)
		return
	}

	log.Debugf("responding to challenge request")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, key)
}

func (a *Acme) RunServer(stopCh <-chan struct{}) {

	portIntStr := a.kubelego.LegoHTTPPort()
	port := fmt.Sprintf(":%d", portIntStr.IntValue())

	// listen on port
	listener, err := net.Listen("tcp", port)
	if err != nil {
		a.Log().Fatalf("error starting http server on %s: %s", port, err)
	}

	mux := a.Mux()

	a.Log().Infof("server listening on http://%s/", port)

	// handle stop signal
	go func() {
		<-stopCh
		a.Log().Infof("stopping server listening on http://%s/", port)
		listener.Close()
	}()

	http.Serve(listener, mux)
}
