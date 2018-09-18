PROTO_FILES := $(wildcard *.proto)
PB_GO_FILES := $(patsubst %.proto,%.pb.go,$(PROTO_FILES))

.PHONY: all clean

all: $(PB_GO_FILES)

%.pb.go: %.proto
	protoc --go_out=plugins=grpc:. $?

clean:
	rm -f *.pb.go
