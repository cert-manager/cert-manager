# lego

Let's Encrypt client and ACME library written in Go

[![GoDoc](https://godoc.org/github.com/xenolf/lego?status.svg)](https://godoc.org/github.com/xenolf/lego/acme)
[![Build Status](https://travis-ci.org/xenolf/lego.svg?branch=master)](https://travis-ci.org/xenolf/lego)
[![Docker Pulls](https://img.shields.io/docker/pulls/xenolf/lego.svg)](https://hub.docker.com/r/xenolf/lego/)
[![Dev Chat](https://img.shields.io/badge/dev%20chat-gitter-blue.svg?label=dev+chat)](https://gitter.im/xenolf/lego)
[![Beerpay](https://beerpay.io/xenolf/lego/badge.svg)](https://beerpay.io/xenolf/lego)

## Installation

### Binaries

To get the binary just download the latest release for your OS/Arch from [the release page](https://github.com/xenolf/lego/releases)
and put the binary somewhere convenient. lego does not assume anything about the location you run it from.

### From Docker

```bash
docker run xenolf/lego -h
```

### From the package manager

- [ArchLinux (AUR)](https://aur.archlinux.org/packages/lego-git):

```bash
yaourt -S lego-git
```

### From source

To install from source, just run:

```bash
go get -u github.com/xenolf/lego
```

## Features

- Register with CA
- Obtain certificates, both from scratch or with an existing CSR
- Renew certificates
- Revoke certificates
- Robust implementation of all ACME challenges
  - HTTP (http-01)
  - DNS (dns-01)
  - TLS (tls-alpn-01)
- SAN certificate support
- Comes with multiple optional [DNS providers](https://github.com/xenolf/lego/tree/master/providers/dns)
- [Custom challenge solvers](https://github.com/xenolf/lego/wiki/Writing-a-Challenge-Solver)
- Certificate bundling
- OCSP helper function

Please keep in mind that CLI switches and APIs are still subject to change.

When using the standard `--path` option, all certificates and account configurations are saved to a folder *.lego* in the current working directory.

## Usage

```text
NAME:
   lego - Let's Encrypt client written in Go

USAGE:
   lego [global options] command [command options] [arguments...]

COMMANDS:
     run      Register an account, then create and install a certificate
     revoke   Revoke a certificate
     renew    Renew a certificate
     dnshelp  Shows additional help for the --dns global option
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --domains value, -d value   Add a domain to the process. Can be specified multiple times.
   --csr value, -c value       Certificate signing request filename, if an external CSR is to be used
   --server value, -s value    CA hostname (and optionally :port). The server certificate must be trusted in order to avoid further modifications to the client. (default: "https://acme-v02.api.letsencrypt.org/directory")
   --email value, -m value     Email used for registration and recovery contact.
   --filename value            Filename of the generated certificate
   --accept-tos, -a            By setting this flag to true you indicate that you accept the current Let's Encrypt terms of service.
   --eab                       Use External Account Binding for account registration. Requires --kid and --hmac.
   --kid value                 Key identifier from External CA. Used for External Account Binding.
   --hmac value                MAC key from External CA. Should be in Base64 URL Encoding without padding format. Used for External Account Binding.
   --key-type value, -k value  Key type to use for private keys. Supported: rsa2048, rsa4096, rsa8192, ec256, ec384 (default: "rsa2048")
   --path value                Directory to use for storing the data (default: "./.lego")
   --exclude value, -x value   Explicitly disallow solvers by name from being used. Solvers: "http-01", "dns-01", "tls-alpn-01".
   --webroot value             Set the webroot folder to use for HTTP based challenges to write directly in a file in .well-known/acme-challenge
   --memcached-host value      Set the memcached host(s) to use for HTTP based challenges. Challenges will be written to all specified hosts.
   --http value                Set the port and interface to use for HTTP based challenges to listen on. Supported: interface:port or :port
   --tls value                 Set the port and interface to use for TLS based challenges to listen on. Supported: interface:port or :port
   --dns value                 Solve a DNS challenge using the specified provider. Disables all other challenges. Run 'lego dnshelp' for help on usage.
   --http-timeout value        Set the HTTP timeout value to a specific value in seconds. The default is 10 seconds. (default: 0)
   --dns-timeout value         Set the DNS timeout value to a specific value in seconds. The default is 10 seconds. (default: 0)
   --dns-resolvers value       Set the resolvers to use for performing recursive DNS queries. Supported: host:port. The default is to use the system resolvers, or Google's DNS resolvers if the system's cannot be determined.
   --pem                       Generate a .pem file by concatenating the .key and .crt files together.
   --help, -h                  show help
   --version, -v               print the version
```

### Sudo

The CLI does not require root permissions but needs to bind to port 80 and 443 for certain challenges.
To run the CLI without sudo, you have four options:

- Use setcap 'cap_net_bind_service=+ep' /path/to/program
- Pass the `--http` or/and the `--tls` option and specify a custom port to bind to. In this case you have to forward port 80/443 to these custom ports (see [Port Usage](#port-usage)).
- Pass the `--webroot` option and specify the path to your webroot folder. In this case the challenge will be written in a file in `.well-known/acme-challenge/` inside your webroot.
- Pass the `--dns` option and specify a DNS provider.

### Port Usage

By default lego assumes it is able to bind to ports 80 and 443 to solve challenges.
If this is not possible in your environment, you can use the `--http` and `--tls` options to instruct
lego to listen on that interface:port for any incoming challenges.

If you are using this option, make sure you proxy all of the following traffic to these ports.

HTTP Port:

- All plaintext HTTP requests to port 80 which begin with a request path of `/.well-known/acme-challenge/` for the HTTP challenge.

TLS Port:

- All TLS handshakes on port 443 for the TLS-ALPN challenge.

This traffic redirection is only needed as long as lego solves challenges. As soon as you have received your certificates you can deactivate the forwarding.

### CLI Example

Assumes the `lego` binary has permission to bind to ports 80 and 443. You can get a pre-built binary from the [releases](https://github.com/xenolf/lego/releases) page.
If your environment does not allow you to bind to these ports, please read [Port Usage](#port-usage).

Obtain a certificate:

```bash
lego --email="foo@bar.com" --domains="example.com" run
```

(Find your certificate in the `.lego` folder of current working directory.)

To renew the certificate:

```bash
lego --email="foo@bar.com" --domains="example.com" renew
```

To renew the certificate only if it expires within 30 days

```bash
lego --email="foo@bar.com" --domains="example.com" renew --days 30
```

Obtain a certificate using the DNS challenge and AWS Route 53:

```bash
AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=my_id AWS_SECRET_ACCESS_KEY=my_key lego --email="foo@bar.com" --domains="example.com" --dns="route53" run
```

Note that `--dns=foo` implies `--exclude=http-01`. lego will not attempt other challenges if you've told it to use DNS instead.

Obtain a certificate given a certificate signing request (CSR) generated by something else:

```bash
lego --email="foo@bar.com" --csr=/path/to/csr.pem run
```

(lego will infer the domains to be validated based on the contents of the CSR, so make sure the CSR's Common Name and optional SubjectAltNames are set correctly.)

lego defaults to communicating with the production Let's Encrypt ACME server. If you'd like to test something without issuing real certificates, consider using the staging endpoint instead:

```bash
lego --server=https://acme-staging-v02.api.letsencrypt.org/directory …
```

## DNS Challenge API Details

### AWS Route 53

The following AWS IAM policy document describes the permissions required for lego to complete the DNS challenge.
Replace `<INSERT_YOUR_HOSTED_ZONE_ID_HERE>` with the Route 53 zone ID of the domain you are authorizing.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:GetChange",
                "route53:ListHostedZonesByName"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/<INSERT_YOUR_HOSTED_ZONE_ID_HERE>"
            ]
        }
    ]
}
```

## ACME Library Usage

A valid, but bare-bones example use of the acme package:

```go
// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}
func (u MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// Create a user. New accounts need an email and private key to start.
const rsaKeySize = 2048
privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
if err != nil {
	log.Fatal(err)
}
myUser := MyUser{
	Email: "you@yours.com",
	key: privateKey,
}

// A client facilitates communication with the CA server. This CA URL is
// configured for a local dev instance of Boulder running in Docker in a VM.
client, err := acme.NewClient("http://192.168.99.100:4000/directory", &myUser, acme.RSA2048)
if err != nil {
  log.Fatal(err)
}

// We specify an http port of 5002 and an tls port of 5001 on all interfaces
// because we aren't running as root and can't bind a listener to port 80 and 443
// (used later when we attempt to pass challenges). Keep in mind that we still
// need to proxy challenge traffic to port 5002 and 5001.
client.SetHTTPAddress(":5002")
client.SetTLSAddress(":5001")

// New users will need to register
reg, err := client.Register()
if err != nil {
	log.Fatal(err)
}
myUser.Registration = reg

// SAVE THE USER.

// The client has a URL to the current Let's Encrypt Subscriber
// Agreement. The user will need to agree to it.
err = client.AgreeToTOS()
if err != nil {
	log.Fatal(err)
}

// The acme library takes care of completing the challenges to obtain the certificate(s).
// The domains must resolve to this machine or you have to use the DNS challenge.
bundle := false
certificates, failures := client.ObtainCertificate([]string{"mydomain.com"}, bundle, nil, false)
if len(failures) > 0 {
	log.Fatal(failures)
}

// Each certificate comes back with the cert bytes, the bytes of the client's
// private key, and a certificate URL. SAVE THESE TO DISK.
fmt.Printf("%#v\n", certificates)

// ... all done.
```

## ACME v1

lego introduced support for ACME v2 in [v1.0.0](https://github.com/xenolf/lego/releases/tag/v1.0.0), if you still need to utilize ACME v1, you can do so by using the [v0.5.0](https://github.com/xenolf/lego/releases/tag/v0.5.0) version.
