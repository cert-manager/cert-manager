package acme

import (
	"sync"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	"github.com/Sirupsen/logrus"
	"golang.org/x/crypto/acme"
)

type Acme struct {
	kubelego.Acme

	log            *logrus.Entry
	kubelego       kubelego.KubeLego
	acmeAccountURI string
	acmeClient     *acme.Client
	acmeAccount    *acme.Account

	// challenge storage and its mutex
	challengesMutex       sync.RWMutex
	challengesHostToToken map[string]string
	challengesTokenToKey  map[string]string

	notFound string // string displayed for 404 messages
	id       string // identification (random string)

}

type acmeAccountRegistration struct {
	URI string `json:"uri,omitempty"`
}
