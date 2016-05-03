package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/simonswine/kube-lego/pkg/kubelego_const"

	"github.com/xenolf/lego/acme"
)

func (a *Acme) GetEmail() string {
	return a.kubelego.LegoEmail()
}

func (a *Acme) GetRegistration() *acme.RegistrationResource {
	return a.registration
}

func (a *Acme) GetPrivateKey() crypto.PrivateKey {
	return a.privateKey
}

func (a *Acme) createUser() error {
	privateKeyPem, privateKey, err := a.generatePrivateKey()
	if err != nil {
		return err
	}
	a.privateKey = privateKey

	legoClient, err := acme.NewClient(a.kubelego.LegoURL(), a, kubelego.AcmeKeyType)
	if err != nil {
		return err
	}

	reg, err := legoClient.Register()
	if err != nil {
		return err
	}
	a.registration = reg

	err = legoClient.AgreeToTOS()
	if err != nil {
		return err
	}

	// persistence of user
	regJson, err := json.Marshal(*reg)
	if err != nil {
		return err
	}

	return a.kubelego.SaveAcmeUser(
		map[string][]byte{
			kubelego.AcmePrivateKey:   privateKeyPem,
			kubelego.AcmeRegistration: regJson,
		},
	)
}

func (a *Acme) getUser() error {

	userData, err := a.kubelego.AcmeUser()
	if err != nil {
		return err
	}

	privateKeyData, ok := userData[kubelego.AcmePrivateKey]
	if !ok {
		return fmt.Errorf("Could not find acme private key with key '%s'", kubelego.AcmePrivateKey)
	}
	block, _ := pem.Decode(privateKeyData)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	regData, ok := userData[kubelego.AcmeRegistration]
	if !ok {
		return fmt.Errorf("Could not find acme registration with key '%s'", kubelego.AcmeRegistration)
	}
	reg := acme.RegistrationResource{}
	err = json.Unmarshal(regData, &reg)
	if err != nil {
		return err
	}

	a.registration = &reg
	a.privateKey = privateKey

	return nil
}

func (a *Acme) generatePrivateKey() ([]byte, *rsa.PrivateKey, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, kubelego.RsaKeySize)
	if err != nil {
		return []byte{}, nil, err
	}

	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	return pem.EncodeToMemory(block), privateKey, nil

}
