package acme

import (
	"crypto"
	"sync"

	"github.com/simonswine/kube-lego/pkg/kubelego_const"

	"github.com/Sirupsen/logrus"
	"github.com/xenolf/lego/acme"
)

type Acme struct {
	kubelego.Acme

	log          *logrus.Entry
	kubelego     kubelego.KubeLego
	registration *acme.RegistrationResource
	privateKey   crypto.PrivateKey
	acmeClient   *acme.Client

	// challenge storage and its mutex
	challengesMutex       sync.RWMutex
	challengesHostToToken map[string]string
	challengesTokenToKey  map[string]string

	notFound string // string displayed for 404 messages
	id       string // identification (random string)

}
