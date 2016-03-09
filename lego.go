package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/simonswine/kube-lego/acme"
	"k8s.io/kubernetes/pkg/api"
)

const rsaKeySize = 2048
const TLSRegistration = "registration.json"
const acmeKeyType = acme.RSA2048

type LegoUser struct {
	kubeLego     *KubeLego
	registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u LegoUser) GetEmail() string {
	return u.kubeLego.LegoEmail
}

func (u LegoUser) GetRegistration() *acme.RegistrationResource {
	return u.registration
}

func (u LegoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (kl *KubeLego) generatePrivateKey() ([]byte, *rsa.PrivateKey, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return []byte{}, nil, err
	}

	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	return pem.EncodeToMemory(block), privateKey, nil

}

func (kl *KubeLego) createUser() (*LegoUser, error) {
	privateKeyPem, privateKey, err := kl.generatePrivateKey()
	if err != nil {
		return nil, err
	}

	user := LegoUser{
		key:      privateKey,
		kubeLego: kl,
	}

	legoClient, err := acme.NewClient(kl.LegoURL, &user, acmeKeyType)
	if err != nil {
		return nil, err
	}

	reg, err := legoClient.Register()
	if err != nil {
		return nil, err
	}
	user.registration = reg

	err = legoClient.AgreeToTOS()
	if err != nil {
		return nil, err
	}

	// persistence of user
	regJson, err := json.Marshal(*reg)
	if err != nil {
		return nil, err
	}

	secret := api.Secret{
		ObjectMeta: api.ObjectMeta{
			Name: kl.LegoSecretName,
		},
		Type: api.SecretTypeTLS,
	}
	secret.Data = make(map[string][]byte)
	secret.Data[api.TLSPrivateKeyKey] = privateKeyPem
	secret.Data[api.TLSCertKey] = []byte{}
	secret.Data[TLSRegistration] = regJson

	kl.CreateSecret(
		kl.Namespace(),
		&secret,
	)

	return &user, nil
}

func (kl *KubeLego) getUser() (*LegoUser, error) {

	secret, err := kl.GetSecret(kl.LegoSecretName, kl.Namespace())
	if err != nil {
		log.Printf("No secret '%s' found in namespace '%s'", kl.LegoSecretName, kl.Namespace())

		return kl.createUser()
	}

	block, _ := pem.Decode(secret.Data[api.TLSPrivateKeyKey])
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	user := LegoUser{
		kubeLego: kl,
		key:      privateKey,
	}

	reg := acme.RegistrationResource{}
	err = json.Unmarshal(
		secret.Data[TLSRegistration],
		&reg,
	)
	if err != nil {
		return nil, err
	}
	user.registration = &reg

	return &user, nil
}

func (kl *KubeLego) paramsLego() error {

	kl.LegoEmail = os.Getenv("LEGO_EMAIL")
	if len(kl.LegoEmail) == 0 {
		return errors.New("Please provide an email address for cert recovery in LEGO_EMAIL")
	}

	kl.LegoSecretName = os.Getenv("LEGO_SECRET_NAME")
	if len(kl.LegoSecretName) == 0 {
		kl.LegoSecretName = "kube-lego-account"
	}

	kl.LegoServiceName = os.Getenv("LEGO_SERVICE_NAME")
	if len(kl.LegoServiceName) == 0 {
		kl.LegoServiceName = "kube-lego"
	}

	httpPortStr := os.Getenv("LEGO_PORT")
	if len(httpPortStr) == 0 {
		kl.LegoHTTPPort = 8080
	} else {
		i, err := strconv.Atoi("-42")
		if err != nil {
			return err
		}
		if i <= 0 || i >= 65535 {
			return fmt.Errorf("Wrong port: %d", i)
		}
		kl.LegoHTTPPort = i

	}

	return nil
}

func (kl *KubeLego) InitLego() error {
	log.Print("initialize lego acme connection")

	err := kl.paramsLego()
	if err != nil {
		return err
	}

	user, err := kl.getUser()
	if err != nil {
		return err
	}
	kl.legoUser = user

	legoClient, err := acme.NewClient(kl.LegoURL, kl.legoUser, acmeKeyType)
	if err != nil {
		return err
	}
	kl.LegoClient = legoClient

	kl.LegoClient.SetHTTPAddress(":8008")

	return nil
}
