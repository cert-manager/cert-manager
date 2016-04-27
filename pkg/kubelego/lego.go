package kubelego

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/simonswine/kube-lego/pkg/kubelego_const"
	"github.com/simonswine/kube-lego/pkg/secret"

	"github.com/xenolf/lego/acme"
	k8sApi "k8s.io/kubernetes/pkg/api"
)


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

	privateKey, err := rsa.GenerateKey(rand.Reader, kubelego.RsaKeySize)
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

	legoClient, err := acme.NewClient(kl.LegoURL, &user, kubelego.AcmeKeyType)
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

	secretAccount := secret.New(kl, kl.LegoNamespace, kl.LegoSecretName)

	secretAccount.SecretApi.Type = k8sApi.SecretTypeTLS
	secretAccount.SecretApi.Data = map[string][]byte{
		k8sApi.TLSPrivateKeyKey: privateKeyPem,
		k8sApi.TLSCertKey: []byte{},
		kubelego.TLSRegistration: regJson,
	}

	err = secretAccount.Save()
	if err != nil{
		return nil, err
	}

	return &user, nil
}

func (kl *KubeLego) getUser() (*LegoUser, error) {

	secretAccount := secret.New(kl, kl.LegoNamespace, kl.LegoSecretName)
	if ! secretAccount.Exists() {
		log.Printf("No account secret '%s' found in namespace '%s'", kl.LegoSecretName, kl.Namespace())

		return kl.createUser()
	}

	block, _ := pem.Decode(secretAccount.SecretApi.Data[k8sApi.TLSPrivateKeyKey])
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
		secretAccount.SecretApi.Data[kubelego.TLSRegistration],
		&reg,
	)
	if err != nil {
		return nil, err
	}
	user.registration = &reg

	return &user, nil
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

	legoClient, err := acme.NewClient(kl.LegoURL, kl.legoUser, kubelego.AcmeKeyType)
	if err != nil {
		return err
	}

	legoClient.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01, acme.DNS01})

	kl.legoClient = legoClient
	kl.LegoClient().SetHTTPAddress(fmt.Sprintf(":%d", kl.LegoHTTPPort.IntValue()))

	return nil
}
