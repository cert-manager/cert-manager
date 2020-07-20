package designate

import (
	"os"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/pkg/errors"
)

type Auth struct {
	authURL,
	regionName,
	tokenID,
	userName,
	userDomainName,
	password,
	projectName,
	projectDomainName,
	zoneName string
}

func NewAuthFromENV() *Auth {
	return &Auth{
		authURL:           os.Getenv("OS_AUTH_URL"),
		userName:          os.Getenv("OS_USER_NAME"),
		userDomainName:    os.Getenv("OS_USER_DOMAIN_NAME"),
		password:          os.Getenv("OS_PASSWORD"),
		regionName:        os.Getenv("OS_REGION_NAME"),
		projectName:       os.Getenv("OS_PROJECT_NAME"),
		projectDomainName: os.Getenv("OS_PROJECT_DOMAIN_NAME"),
		zoneName:          os.Getenv("OS_ZONE_NAME"),
	}
}

func NewAuthenticatedProviderClient(auth *Auth) (*gophercloud.ProviderClient, error) {
	opts := &tokens.AuthOptions{
		IdentityEndpoint: auth.authURL,
		Username:         auth.userName,
		DomainName:       auth.userDomainName,
		Password:         auth.password,
		AllowReauth:      true,
		Scope: tokens.Scope{
			ProjectName: auth.projectName,
			DomainName:  auth.projectDomainName,
		},
	}

	provider, err := openstack.NewClient(auth.authURL)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize openstack client")
	}

	err = openstack.AuthenticateV3(provider, opts, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "authentication failed")
	}

	if provider.TokenID == "" {
		return nil, errors.New("token is empty. authentication failed")
	}
	return provider, nil
}
