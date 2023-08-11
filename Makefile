VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.version=$(VERSION)"
OSARCH=$(shell go env GOHOSTOS)-$(shell go env GOHOSTARCH)

SCEPSERVER=\
	scepserver-linux-amd64 \
	scepserver-linux-arm \
	scepserver-darwin-amd64 \
	scepserver-darwin-arm64 \
	scepserver-freebsd-amd64 \
	scepserver-windows-amd64.exe

my: scepserver-$(OSARCH)

docker: scepserver-linux-amd64

$(SCEPSERVER):
	GOOS=$(word 2,$(subst -, ,$@)) GOARCH=$(word 3,$(subst -, ,$(subst .exe,,$@))) go build $(LDFLAGS) -o $@ ./cmd/scepserver

%-$(VERSION).zip: %.exe
	rm -f $@
	zip $@ $<

%-$(VERSION).zip: %
	rm -f $@
	zip $@ $<

release: $(foreach bin,$(SCEPSERVER),$(subst .exe,,$(bin))-$(VERSION).zip)

clean:
	rm -f scepserver-*

test:
	go test -cover ./...

# don't run race tests by default. see https://github.com/etcd-io/bbolt/issues/187
test-race:
	go test -cover -race ./...

.PHONY: my docker $(SCEPSERVER) release clean test test-race
