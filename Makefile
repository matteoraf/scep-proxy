VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.version=$(VERSION)"
OSARCH=$(shell go env GOHOSTOS)-$(shell go env GOHOSTARCH)

SCEPCLIENT=\
	scepclient-linux-amd64 \
	scepclient-linux-arm \
	scepclient-darwin-amd64 \
	scepclient-darwin-arm64 \
	scepclient-freebsd-amd64 \
	scepclient-windows-amd64.exe

SCEPSERVER=\
	scepserver-linux-amd64 \
	scepserver-linux-arm \
	scepserver-darwin-amd64 \
	scepserver-darwin-arm64 \
	scepserver-freebsd-amd64 \
	scepserver-windows-amd64.exe

SCEPPROXY=\
	scepproxy-linux-amd64 \
	scepproxy-linux-arm \
	scepproxy-darwin-amd64 \
	scepproxy-darwin-arm64 \
	scepproxy-freebsd-amd64 \
	scepproxy-windows-amd64.exe

my: scepclient-$(OSARCH) scepserver-$(OSARCH) scepproxy-$(OSARCH)

docker: scepclient-linux-amd64 scepserver-linux-amd64 scepproxy-linux-amd64

$(SCEPCLIENT):
	GOOS=$(word 2,$(subst -, ,$@)) GOARCH=$(word 3,$(subst -, ,$(subst .exe,,$@))) go build $(LDFLAGS) -o $@ ./cmd/scepclient

$(SCEPSERVER):
	GOOS=$(word 2,$(subst -, ,$@)) GOARCH=$(word 3,$(subst -, ,$(subst .exe,,$@))) go build $(LDFLAGS) -o $@ ./cmd/scepserver

$(SCEPPROXY):
	GOOS=$(word 2,$(subst -, ,$@)) GOARCH=$(word 3,$(subst -, ,$(subst .exe,,$@))) go build $(LDFLAGS) -o $@ ./cmd/scepproxy

%-$(VERSION).zip: %.exe
	rm -f $@
	zip $@ $<

%-$(VERSION).zip: %
	rm -f $@
	zip $@ $<

release: $(foreach bin,$(SCEPCLIENT) $(SCEPSERVER) $(SCEPPROXY),$(subst .exe,,$(bin))-$(VERSION).zip)

clean:
	rm -f scepclient-* scepserver-* scepproxy-*

test:
	go test -cover ./...

# don't run race tests by default. see https://github.com/etcd-io/bbolt/issues/187
test-race:
	go test -cover -race ./...

.PHONY: my docker $(SCEPCLIENT) $(SCEPSERVER) $(SCEPPROXY) release clean test test-race
