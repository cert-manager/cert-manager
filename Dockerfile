FROM golang:1.5

RUN go get github.com/tools/godep

WORKDIR /go/src/github.com/simonswine/kube-lego/
ADD *.go ./
ADD Godeps ./Godeps/
ADD acme ./acme/

RUN godep go test && godep go build

CMD ./kube-lego
