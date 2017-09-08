# ubuntu-nsenter

This is a simple Docker image that contains a dynamically linked version of
nsenter for Ubuntu 14.04. It is used in the e2e CI environment in order to
install socat on a Travis CI host.

You can use it like so:

```
$ docker build -t ubuntu-nsenter .
$ docker run -v /usr/local/bin:/hostbin ubuntu-nsenter cp /nsenter /hostbin/nsenter
```
